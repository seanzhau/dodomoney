package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image/color"
	"image/png"
	"io"
	"log"
	"math"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	qrcode "github.com/skip2/go-qrcode"
	"github.com/spf13/viper"
	"github.com/tyler-smith/go-bip39"
)

type EntryLabels struct {
	MnemonicEntry            *widget.Entry
	HexEntry                 *widget.Entry
	TaprootEntry             *widget.Entry
	TaprootHexEntry          *widget.Entry
	TaprootBalanceEntry      *widget.Entry
	LegacyEntry              *widget.Entry
	LegacyHexEntry           *widget.Entry
	LegacyBalanceEntry       *widget.Entry
	P2pkhEntry               *widget.Entry
	P2pkhHexEntry            *widget.Entry
	P2pkhBalanceEntry        *widget.Entry
	NativeSegWitEntry        *widget.Entry
	NativeSegWitHexEntry     *widget.Entry
	NativeSegWitBalanceEntry *widget.Entry
	NestedSegWitEntry        *widget.Entry
	NestedSegWitHexEntry     *widget.Entry
	NestedSegWitBalanceEntry *widget.Entry
	P2shEntry                *widget.Entry
	P2shHexEntry             *widget.Entry
	P2shBalanceEntry         *widget.Entry
	P2wshEntry               *widget.Entry
	P2wshHexEntry            *widget.Entry
	P2wshBalanceEntry        *widget.Entry
	P2wshP2shEntry           *widget.Entry
	P2wshP2shHexEntry        *widget.Entry
	P2wshP2shBalanceEntry    *widget.Entry
	EthemeumEntry            *widget.Entry
	EthemeumHexEntry         *widget.Entry
	EthemeumBalanceEntry     *widget.Entry
}

type customTheme struct {
	fyne.Theme
}

type AddressInfo struct {
	Address string
	Balance string
}

// ---------------------------------------------------------------- Loading Window ----------------------------------------------------------------
// Loading local address library
func main() {
	dodoMoney := app.New()
	loadingWindow := dodoMoney.NewWindow("DodoMoney | Loading ...")

	// reading config file
	viper.SetConfigFile("conf/config.yaml")
	if err := viper.ReadInConfig(); err != nil {
		log.Printf("Loading failed: %v", err)
		return
	}

	btcFile := viper.GetString("default.btc")
	ethFile := viper.GetString("default.eth")
	mnemonic := viper.GetString("default.mnemonic")
	keyChoice := viper.GetString("default.choice")
	calcStep := viper.GetString("default.step")
	threadStep := viper.GetString("default.thread")

	// Loading BTC & ETH file
	progressBTC := widget.NewProgressBar()
	progressETH := widget.NewProgressBar()

	// close
	exitBtn := widget.NewButton("Cancel", func() {
		loadingWindow.Close()
	})

	loadingWindow.SetContent(container.NewVBox(
		widget.NewLabel("BTC:"),
		progressBTC,
		widget.NewLabel("ETH:"),
		progressETH,
		widget.NewLabel(""),
		exitBtn,
	))

	loadingWindow.Resize(fyne.NewSize(600, 260))
	loadingWindow.SetFixedSize(true)
	loadingWindow.Show()

	done := make(chan struct{})
	var balanceBTCMap, balanceETHMap map[string]AddressInfo

	go func() {
		balanceBTCMap = readFileWithProgress(btcFile, progressBTC, loadingWindow)
		if balanceBTCMap == nil {
			dodoMoney.SendNotification(fyne.NewNotification("Error", "Failed to read BTC file."))
			os.Exit(1)
		}

		balanceETHMap = readFileWithProgress(ethFile, progressETH, loadingWindow)
		if balanceETHMap == nil {
			dodoMoney.SendNotification(fyne.NewNotification("Error", "Failed to read ETH file."))
			os.Exit(1)
		}

		done <- struct{}{}
	}()

	go func() {
		<-done
		dodoMoney.SendNotification(fyne.NewNotification("Success", "BTC & ETH library load complete!"))

		log.Printf("Loading App Window.")

		// Show App Window
		if err := dodoWallet(mnemonic, keyChoice, calcStep, threadStep, balanceBTCMap, balanceETHMap, dodoMoney); err != nil {
			log.Printf("Load app window failed: %v", err)
			dialog.ShowError(fmt.Errorf("Load app window failed: %v", err), loadingWindow)
			return
		} else {
			loadingWindow.Close()
		}
	}()
	dodoMoney.Run()
}

// ================================================================ read file ================================================================
func countLines(file string) (int, error) {
	f, err := os.Open(file)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	lineCount := 0
	for {
		_, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
		lineCount++
	}
	return lineCount, nil
}

func readFileWithProgress(file string, progressBar *widget.ProgressBar, loadingWindow fyne.Window) map[string]AddressInfo {
	totalLines, err := countLines(file)
	if totalLines == 0 {
		dialog.ShowInformation("ERROR", fmt.Sprintf("Please check %s file exist.", file), loadingWindow)
		return nil
	}

	if err != nil {
		progressBar.SetValue(0)
		return nil
	}

	f, err := os.Open(file)
	if err != nil {
		progressBar.SetValue(0)
		return nil
	}
	defer f.Close()

	addrMap := make(map[string]AddressInfo)
	scanner := bufio.NewScanner(f)
	currentLine := 0

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			addrMap[parts[0]] = AddressInfo{
				Address: parts[0],
				Balance: parts[1],
			}
		}

		currentLine++
		percent := float64(currentLine) / float64(totalLines)
		progressBar.SetValue(percent)

		loadingWindow.Canvas().Refresh(progressBar)
	}

	if err := scanner.Err(); err != nil {
		progressBar.SetValue(0)
		return nil
	}

	return addrMap
}

// ---------------------------------------------------------------- app Window ----------------------------------------------------------------
func dodoWallet(mnemonicStep, keyChoice, calcStep, threadStep string, balanceBTCMap, balanceETHMap map[string]AddressInfo, dodoMoney fyne.App) error {
	stopChannel := make(chan bool)
	var currentMode string
	var lastKey, currentKey *big.Int
	var minHex, maxHex string
	var isGenerating int32 = 0
	var err error

	defer func() {
		if r := recover(); r != nil {
			log.Printf("Error in open main window: %v", r)
		}
	}()

	appWindow := dodoMoney.NewWindow("Dodo Money")
	if appWindow == nil {
		return fmt.Errorf("Failed to initialize appWindow")
	}

	// App window setting
	fyne.CurrentApp().Settings().SetTheme(&customTheme{fyne.CurrentApp().Settings().Theme()})

	// initialize app window size
	appWidth := float32(1500)
	appHeight := float32(690)

	// initialize grid
	gridSize := 16
	gridArray := make([]bool, gridSize*gridSize)
	gridView, buttons := initializeGrid(gridSize, gridArray)

	// initialize input
	privateKeyInput := initializeHexInput()
	wifInput := initializeWifInput()
	publicKeyInput := initializePublicKeyInput()
	mnemonicInput := initializeMnemonicInput()

	// initialize wallet
	walletKeys := initializeWalletKeys()

	// minHex/maxHex
	minEntry := widget.NewEntry()
	maxEntry := widget.NewEntry()

	// ----------------------------- grid -----------------------------
	manualCustomBtn := widget.NewButton("Generate by Grid", func() {
		if atomic.LoadInt32(&isGenerating) == 1 {
			dialog.ShowInformation("Notice", fmt.Sprintf("%s is running, please click stop butten.", currentMode), appWindow)
			log.Printf("Job is running, please click stop butten.")
			return
		}

		walletKeys.MnemonicEntry.SetText("")
		lastKey, err = bit2Hex(gridArray)
		if err != nil {
			dialog.ShowInformation("ERROR", err.Error(), appWindow)
			initializeWindows(minHex, maxHex, mnemonicInput, privateKeyInput, wifInput, publicKeyInput, minEntry, maxEntry, gridSize, buttons, gridArray, walletKeys)
			return
		}

		generateWalletAddressbyPrivateKey(lastKey, walletKeys, balanceBTCMap, balanceETHMap, appWindow, dodoMoney)
	})

	// ----------------------------- HEX -----------------------------
	manualHexBtn := widget.NewButton("Gen", func() {
		if privateKeyInput.Text == "" {
			dialog.ShowInformation("Notice", "Please input hex!", appWindow)
			return
		}

		if atomic.LoadInt32(&isGenerating) == 1 {
			dialog.ShowInformation("Notice", fmt.Sprintf("%s is running, please click stop butten.", currentMode), appWindow)
			log.Printf("Job is running, please click stop butten.")
			return
		}

		walletKeys.MnemonicEntry.SetText("")
		lastKey, err = validatePrivateKeyHex(privateKeyInput.Text)
		if err != nil {
			dialog.ShowInformation("ERROR", err.Error(), appWindow)
			return
		}

		updateGridbyPrivateKey(lastKey, gridSize, buttons, gridArray)
		generateWalletAddressbyPrivateKey(lastKey, walletKeys, balanceBTCMap, balanceETHMap, appWindow, dodoMoney)
	})

	// ----------------------------- WIF -----------------------------
	manualWifBtn := widget.NewButton("Gen", func() {
		if wifInput.Text == "" {
			dialog.ShowInformation("Notice", "Please input WIF!", appWindow)
			return
		}

		if atomic.LoadInt32(&isGenerating) == 1 {
			dialog.ShowInformation("Notice", fmt.Sprintf("%s is running, please click stop butten.", currentMode), appWindow)
			log.Printf("Job is running, please click stop butten.")
			return
		}

		walletKeys.MnemonicEntry.SetText("")
		lastKey, err = generatePrivateKeybyWif(wifInput.Text)
		if err != nil {
			dialog.ShowInformation("ERROR", err.Error(), appWindow)
			return
		}

		updateGridbyPrivateKey(lastKey, gridSize, buttons, gridArray)
		generateWalletAddressbyPrivateKey(lastKey, walletKeys, balanceBTCMap, balanceETHMap, appWindow, dodoMoney)
	})

	// ----------------------------- publicKey -----------------------------
	manualPublicKeyBtn := widget.NewButton("Gen", func() {
		if publicKeyInput.Text == "" {
			dialog.ShowInformation("Notice", "Please input public key!", appWindow)
			return
		}

		if atomic.LoadInt32(&isGenerating) == 1 {
			dialog.ShowInformation("Notice", fmt.Sprintf("%s is running, please click stop butten.", currentMode), appWindow)
			log.Printf("Job is running, please click stop butten.")
			return
		}

		for i := 0; i < gridSize*gridSize; i++ {
			updateGridbySelect(buttons[i], i, gridArray, false)
		}
		generateWalletAddressbyPublicKey(publicKeyInput.Text, walletKeys, balanceBTCMap, balanceETHMap, appWindow, dodoMoney)
	})

	// ----------------------------- mnemonic -----------------------------
	var mnLength int

	// mnemonic length
	mnemonicRange := []string{"12", "15", "18", "21", "24"}
	mnemonicSelect := widget.NewSelect(mnemonicRange, func(selected string) {
		if atomic.LoadInt32(&isGenerating) == 1 {
			dialog.ShowInformation("Notice", fmt.Sprintf("%s is running, please click stop butten.", currentMode), appWindow)
			log.Printf("Job is running, please click stop butten.")
			return
		}

		mnLength, err = strconv.Atoi(selected)
		if err != nil {
			log.Printf("conv failed: %v", err)
			return
		}
	})
	mnemonicSelect.SetSelected(mnemonicStep)

	mnemonicBtn := widget.NewButton("Generate Mnemonic", func() {
		if atomic.LoadInt32(&isGenerating) == 1 {
			dialog.ShowInformation("Notice", fmt.Sprintf("%s is running, please click stop butten.", currentMode), appWindow)
			log.Printf("Job is running, please click stop butten.")
			return
		}

		keywords := strings.Fields(mnemonicInput.Text)

		for _, word := range keywords {
			index := indexOf(word, bip39.GetWordList())
			if index < 0 {
				log.Printf("The keyword [ %s ] not in BIP39 list.", word)
				bip39Label := widget.NewLabel(fmt.Sprintf("The keyword [ %s ] not in BIP39 list.", word))

				parsedURL, _ := url.Parse("https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt")
				bip39Link := widget.NewHyperlink("Check with BIP-39 words list", parsedURL)

				content := container.NewVBox(
					bip39Label,
					bip39Link,
				)

				dialog.ShowCustom("ERROR", "Close", content, appWindow)
				return
			}
		}

		var mnemonic string
		if len(keywords) == mnLength {
			mnemonic = strings.Join(keywords, " ")
			if !bip39.IsMnemonicValid(mnemonic) {
				log.Printf("The input %d mnemonic [%s] check failed", mnLength, mnemonic)
				dialog.ShowInformation("ERROR", fmt.Sprintf("The input %d mnemonic check failed", mnLength), appWindow)
				initializeWindows(minHex, maxHex, mnemonicInput, privateKeyInput, wifInput, publicKeyInput, minEntry, maxEntry, gridSize, buttons, gridArray, walletKeys)
				return
			}
		} else if len(keywords) > mnLength*2/3 {
			log.Printf("Safety keywords length between 0 - %d，0 will be generate by random.", mnLength*2/3)
			dialog.ShowInformation("ERROR", fmt.Sprintf("Safety keywords length between 0 - %d，0 will be generate by random.", mnLength*2/3), appWindow)
			return
		} else {
			mnemonic = generateMnemonic(keywords, mnLength)
		}

		initializeWindows(minHex, maxHex, mnemonicInput, privateKeyInput, wifInput, publicKeyInput, minEntry, maxEntry, gridSize, buttons, gridArray, walletKeys)
		walletKeys.MnemonicEntry.SetText(mnemonic)
		generateWalletByMnemonic(mnemonic, walletKeys, balanceBTCMap, balanceETHMap, appWindow, dodoMoney)
	})

	var hexRange []string
	hexRange = append(hexRange, "all")

	// puzzle 1 - 160
	for i := 68; i <= 160; i++ {
		hexRange = append(hexRange, "Puzzle-"+strconv.Itoa(i))
	}

	// Select list
	rangeSelect := widget.NewSelect(hexRange, func(selected string) {
		if atomic.LoadInt32(&isGenerating) == 1 {
			dialog.ShowInformation("Notice", fmt.Sprintf("%s is running, please click stop butten.", currentMode), appWindow)
			log.Printf("Job is running, please click stop butten.")
			return
		}

		log.Printf("Hex range: %s", selected)

		if selected != "all" {
			puzzleNum, err := strconv.Atoi(selected[7:])
			if err != nil {
				log.Printf("Error: %e", err)
				return
			}

			minValue := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(puzzleNum-1)), nil)
			minHex = fmt.Sprintf("%064x", minValue)

			maxValue := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(puzzleNum)), nil)
			maxValue.Sub(maxValue, big.NewInt(1))
			maxHex = fmt.Sprintf("%064x", maxValue)
		} else {
			// full size
			minHex = "0000000000000000000000000000000000000000000000000000000000000001"
			maxHex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
		}

		// custom define range
		minEntry.SetText(minHex)
		maxEntry.SetText(maxHex)
	})

	rangeSelect.SetSelected(keyChoice)

	//  ----------------------------- generate by manual -----------------------------
	// Generate and display in grid
	manualRandomBtn := widget.NewButton("Manual", func() {
		if atomic.LoadInt32(&isGenerating) == 1 {
			dialog.ShowInformation("Notice", fmt.Sprintf("%s is running, please click stop butten.", currentMode), appWindow)
			log.Printf("Job is running, please click stop butten.")
			return
		}

		walletKeys.MnemonicEntry.SetText("")
		lastKey, err = generateRandomKeys(minEntry.Text, maxEntry.Text)

		updateGridbyPrivateKey(lastKey, gridSize, buttons, gridArray)
		generateWalletAddressbyPrivateKey(lastKey, walletKeys, balanceBTCMap, balanceETHMap, appWindow, dodoMoney)
	})

	//  ----------------------------- generate by multi thread -----------------------------
	var threadRange []string
	for i := 0; i <= 5; i++ {
		threadRange = append(threadRange, strconv.Itoa(int(math.Pow(2, float64(i)))))
	}

	// thead list
	threadSelect := widget.NewSelect(threadRange, func(selected string) {
		if atomic.LoadInt32(&isGenerating) == 1 {
			dialog.ShowInformation("Notice", fmt.Sprintf("%s is running, please click stop butten.", currentMode), appWindow)
			log.Printf("Job is running, please click stop butten.")
			return
		}
		log.Printf("Thread number: %s", selected)
	})

	threadSelect.SetSelected(threadStep)

	autoRandomBtn := widget.NewButton("Random", func() {
		if atomic.LoadInt32(&isGenerating) == 1 {
			dialog.ShowInformation("Notice", fmt.Sprintf("%s is running, please click stop butten.", currentMode), appWindow)
			log.Printf("Job is running, please click stop butten.")
			return
		}

		if stopChannel != nil {
			close(stopChannel)
			stopChannel = nil
			log.Printf("Stop %s", currentMode)
		}

		currentMode = "random"
		stopChannel = make(chan bool)
		walletKeys.MnemonicEntry.SetText("")

		log.Printf("begin %s", currentMode)
		atomic.StoreInt32(&isGenerating, 1)

		minKey, _ := new(big.Int).SetString(minEntry.Text, 16)
		maxKey, _ := new(big.Int).SetString(maxEntry.Text, 16)
		numThreads, _ := strconv.Atoi(threadSelect.Selected)

		for i := 0; i < numThreads; i++ {
			go func(stopChan chan bool, threadId int) {
				defer func() {
					atomic.StoreInt32(&isGenerating, 0)
					log.Println("Thread exit")
				}()
				for {
					select {
					case <-stopChan:
						if currentKey != nil && currentKey.Cmp(minKey) >= 0 && currentKey.Cmp(maxKey) <= 0 {
							lastKey.Set(currentKey)
							log.Printf("Stop %s，Last key: %064x", currentMode, lastKey)
						} else {
							log.Printf("%064x out off range, use the the min key.", lastKey)
							lastKey.Set(minKey)
						}
						return
					default:
						currentKey, _ = generateRandomKeys(minEntry.Text, maxEntry.Text)

						updateGridbyPrivateKey(currentKey, gridSize, buttons, gridArray)
						generateWalletAddressbyPrivateKey(currentKey, walletKeys, balanceBTCMap, balanceETHMap, appWindow, dodoMoney)
					}
				}
			}(stopChannel, i)
		}
	})

	//  ----------------------------- generate by step -----------------------------
	var stepRange []string

	for i := 0; i <= 10; i++ {
		stepRange = append(stepRange, strconv.Itoa(int(math.Pow(2, float64(i)))))
	}

	stepSelect := widget.NewSelect(stepRange, func(selected string) {
		if atomic.LoadInt32(&isGenerating) == 1 {
			dialog.ShowInformation("Notice", fmt.Sprintf("%s is running, please click stop butten.", currentMode), appWindow)
			log.Printf("Job is running, please click stop butten.")
			return
		}

		log.Printf("hex step: %s", selected)
	})

	stepSelect.SetSelected(calcStep)

	autoSequenceBtn := widget.NewButton("Sequence", func() {
		if atomic.LoadInt32(&isGenerating) == 1 {
			dialog.ShowInformation("Notice", fmt.Sprintf("%s is running, please click stop butten.", currentMode), appWindow)
			log.Printf("Job is running, please click stop butten.")
			return
		}

		if stopChannel != nil {
			close(stopChannel)
			stopChannel = nil
			log.Printf("Sotp %s", currentMode)
		}

		currentMode = "sequence"
		stopChannel = make(chan bool)

		walletKeys.MnemonicEntry.SetText("")
		log.Printf("Stop %s", currentMode)
		atomic.StoreInt32(&isGenerating, 1)

		stepValue, _ := strconv.Atoi(stepSelect.Selected)
		stepIncrement := big.NewInt(int64(stepValue))

		minKey, _ := new(big.Int).SetString(minEntry.Text, 16)
		maxKey, _ := new(big.Int).SetString(maxEntry.Text, 16)

		if lastKey != nil {
			if lastKey.Cmp(minKey) >= 0 && lastKey.Cmp(maxKey) <= 0 {
				currentKey = lastKey
				log.Printf("Last hex key: %064x", currentKey)
				// currentKey.Add(lastKey, stepIncrement)
			} else {
				log.Printf("%064x out off range, use the the min key.", lastKey)
				currentKey = minKey
			}
		} else {
			log.Printf("No last key, start with min key: %064x", minKey)
			currentKey = minKey
			log.Printf("Min key: %064x", currentKey)
		}

		go func(stopChan chan bool) {
			defer func() {
				atomic.StoreInt32(&isGenerating, 0)
				log.Println("Thread exit.")
			}()
			for {
				select {
				case <-stopChan:
					log.Println("Stopping thread...")
					return
				default:
					if currentKey.Cmp(maxKey) > 0 {
						log.Println("Out off hex range")
						return
					}

					updateGridbyPrivateKey(currentKey, gridSize, buttons, gridArray)
					generateWalletAddressbyPrivateKey(currentKey, walletKeys, balanceBTCMap, balanceETHMap, appWindow, dodoMoney)

					currentKey.Add(currentKey, stepIncrement)

					time.Sleep(1 * time.Millisecond)
				}
			}
		}(stopChannel)
	})

	// ----------------------------- stop -----------------------------
	stopRandomBtn := widget.NewButton("Stop", func() {
		if atomic.LoadInt32(&isGenerating) == 0 {
			dialog.ShowInformation("Notice", "No job running", appWindow)
			log.Printf("No job running")
			return
		}

		if stopChannel != nil {
			close(stopChannel)
			stopChannel = nil
			log.Printf("Stop %s", currentMode)

			if currentKey != nil && currentKey.Cmp(big.NewInt(0)) != 0 {
				lastKey = currentKey
				log.Printf("Stop %s，recode last key: %064x", currentMode, lastKey)
			} else {
				lastKey, _ = new(big.Int).SetString(minEntry.Text, 16)
				log.Printf("no job running, use: %064x", lastKey)
			}

			currentMode = ""
			atomic.StoreInt32(&isGenerating, 0)
		}
	})

	// ----------------------------- Inverse Gird -----------------------------
	inverseBtn := widget.NewButton("Inverse Gird", func() {
		if atomic.LoadInt32(&isGenerating) == 1 {
			dialog.ShowInformation("Notice", fmt.Sprintf("%s is running, please click stop butten.", currentMode), appWindow)
			log.Printf("Job is running, please click stop butten.")
			return
		}

		for i := range gridArray {
			gridArray[i] = !gridArray[i]
		}

		lastKey, err = bit2Hex(gridArray)
		if err != nil {
			dialog.ShowInformation("ERROR", err.Error(), appWindow)
			initializeWindows(minHex, maxHex, mnemonicInput, privateKeyInput, wifInput, publicKeyInput, minEntry, maxEntry, gridSize, buttons, gridArray, walletKeys)
			return
		}

		updateGridbyPrivateKey(lastKey, gridSize, buttons, gridArray)
		generateWalletAddressbyPrivateKey(lastKey, walletKeys, balanceBTCMap, balanceETHMap, appWindow, dodoMoney)
	})

	// ----------------------------- Rotate Gird -----------------------------
	rotateBtn := widget.NewButton("Rotate Gird", func() {
		if atomic.LoadInt32(&isGenerating) == 1 {
			dialog.ShowInformation("Notice", fmt.Sprintf("%s is running, please click stop butten.", currentMode), appWindow)
			log.Printf("Job is running, please click stop butten.")
			return
		}

		rotatedArray := make([]bool, len(gridArray))
		for i := 0; i < gridSize; i++ {
			for j := 0; j < gridSize; j++ {
				newPos := j*gridSize + (gridSize - i - 1)
				oldPos := i*gridSize + j
				rotatedArray[newPos] = gridArray[oldPos]
			}
		}
		copy(gridArray, rotatedArray)

		lastKey, err = bit2Hex(gridArray)
		if err != nil {
			dialog.ShowInformation("ERROR", err.Error(), appWindow)
			initializeWindows(minHex, maxHex, mnemonicInput, privateKeyInput, wifInput, publicKeyInput, minEntry, maxEntry, gridSize, buttons, gridArray, walletKeys)
			return
		}

		updateGridbyPrivateKey(lastKey, gridSize, buttons, gridArray)
		generateWalletAddressbyPrivateKey(lastKey, walletKeys, balanceBTCMap, balanceETHMap, appWindow, dodoMoney)
	})

	// ----------------------------- clear -----------------------------
	clearBtn := widget.NewButton("Clear", func() {
		if atomic.LoadInt32(&isGenerating) == 1 {
			dialog.ShowInformation("Notice", fmt.Sprintf("%s is running, please click stop butten.", currentMode), appWindow)
			log.Printf("Job is running, please click stop butten.")
			return
		}
		lastKey = nil

		initializeWindows(minHex, maxHex, mnemonicInput, privateKeyInput, wifInput, publicKeyInput, minEntry, maxEntry, gridSize, buttons, gridArray, walletKeys)
	})

	// ----------------------------- close window -----------------------------
	exitBtn := widget.NewButton("Exit", func() {
		if atomic.LoadInt32(&isGenerating) == 1 {
			dialog.ShowInformation("Notice", fmt.Sprintf("%s is running, please click stop butten.", currentMode), appWindow)
			log.Printf("Job is running, please click stop butten.")
			return
		}

		log.Printf("Quit app.")
		appWindow.Close()
		appWindow = nil
		runtime.GC()
		dodoMoney.Quit()
	})

	// ----------------------------- Grid -----------------------------
	gridLayout := container.NewVBox(
		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/3, 36)), widget.NewLabel("Grid View:")),
		),

		widget.NewSeparator(),

		gridView,
	)

	//  ----------------------------- function -----------------------------
	funcLayout := container.NewVBox(
		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/3, 36)), widget.NewLabel("Mnemonic:")),
		),

		widget.NewSeparator(),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/24-3, 36)), widget.NewLabel("Keywords")),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*7/24, 36)), mnemonicInput),
		),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/24-3, 36)), widget.NewLabel("Length")),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*2/24-3, 36)), mnemonicSelect),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*5/24-3, 36)), mnemonicBtn),
		),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/3, 6))),
		),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*5/24, 36)), widget.NewLabel("Keys:")),
		),

		widget.NewSeparator(),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/24-3, 36)), widget.NewLabel("HEX"), widget.NewLabel("WIF"), widget.NewLabel("PubKey")),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*6/24-2, 36)), privateKeyInput, wifInput, publicKeyInput),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/24-3, 36)), manualHexBtn, manualWifBtn, manualPublicKeyBtn),
		),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/3, 6))),
		),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*5/24, 36)), widget.NewLabel("Range:")),
		),

		widget.NewSeparator(),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*4/24-2, 36)), widget.NewLabel("Range")),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*4/24-2, 36)), rangeSelect),
		),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/24-3, 36)), widget.NewLabel("min"), widget.NewLabel("max")),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*6/24-2, 36)), minEntry, maxEntry),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/24-3, 75)), manualRandomBtn),
		),

		widget.NewSeparator(),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/24-3, 36)), widget.NewLabel("Thread"), widget.NewLabel("Step")),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*2/24-3, 36)), threadSelect, stepSelect),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*4/24-4, 36)), autoRandomBtn, autoSequenceBtn),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/24-2, 75)), stopRandomBtn),
		),

		widget.NewSeparator(),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/3, 36)), manualCustomBtn),
		),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*4/24-2, 36)), inverseBtn),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*4/24-2, 36)), rotateBtn),
		),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/3, 36)), clearBtn),
		),
	)

	// ----------------------------- wallet -----------------------------
	walletLayout := container.NewVBox(
		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/3, 36)), widget.NewLabel("Wallet infomation:")),
		),

		widget.NewSeparator(),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/12, 36)),
				widget.NewButton("Mnemonic", func() {
					generateQRCode("Mnemonic", walletKeys.MnemonicEntry.Text, "", appWindow, dodoMoney)
				}),
			),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*3/12, 36)), walletKeys.MnemonicEntry),
		),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/12, 36)),
				widget.NewButton("HexKey", func() {
					generateQRCode("Hex Key", walletKeys.HexEntry.Text, walletKeys.HexEntry.Text, appWindow, dodoMoney)
				}),
			),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*3/12, 36)), walletKeys.HexEntry),
		),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/12, 36)),
				widget.NewButton("Taproot", func() {
					generateQRCode("Taproot", walletKeys.TaprootEntry.Text, walletKeys.TaprootHexEntry.Text, appWindow, dodoMoney)
				}),
			),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*5/24, 36)), walletKeys.TaprootEntry),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/24-4, 36)), walletKeys.TaprootBalanceEntry),
		),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/12, 36)),
				widget.NewButton("Legacy", func() {
					generateQRCode("Legacy Compressed", walletKeys.LegacyEntry.Text, walletKeys.LegacyHexEntry.Text, appWindow, dodoMoney)
				}),
			),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*5/24, 36)), walletKeys.LegacyEntry),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/24-4, 36)), walletKeys.LegacyBalanceEntry),
		),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/12, 36)),
				widget.NewButton("Nested SegWit", func() {
					generateQRCode("Nested SegWit", walletKeys.NestedSegWitEntry.Text, walletKeys.NestedSegWitHexEntry.Text, appWindow, dodoMoney)
				}),
			),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*5/24, 36)), walletKeys.NestedSegWitEntry),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/24-4, 36)), walletKeys.NestedSegWitBalanceEntry),
		),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/12, 36)),
				widget.NewButton("Native SegWit", func() {
					generateQRCode("Native SegWit", walletKeys.NativeSegWitEntry.Text, walletKeys.NativeSegWitHexEntry.Text, appWindow, dodoMoney)
				}),
			),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*5/24, 36)), walletKeys.NativeSegWitEntry),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/24-4, 36)), walletKeys.NativeSegWitBalanceEntry),
		),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/12, 36)),
				widget.NewButton("P2PKH", func() {
					generateQRCode("Legacy Uncompressed", walletKeys.P2pkhEntry.Text, walletKeys.P2pkhHexEntry.Text, appWindow, dodoMoney)
				}),
			),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*5/24, 36)), walletKeys.P2pkhEntry),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/24-4, 36)), walletKeys.P2pkhBalanceEntry),
		),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/12, 36)),
				widget.NewButton("P2SH", func() {
					generateQRCode("P2SH", walletKeys.P2shEntry.Text, walletKeys.P2shHexEntry.Text, appWindow, dodoMoney)
				}),
			),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*5/24, 36)), walletKeys.P2shEntry),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/24-4, 36)), walletKeys.P2shBalanceEntry),
		),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/12, 36)),
				widget.NewButton("P2WSH", func() {
					generateQRCode("P2WSH", walletKeys.P2wshEntry.Text, walletKeys.P2wshHexEntry.Text, appWindow, dodoMoney)
				}),
			),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*5/24, 36)), walletKeys.P2wshEntry),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/24-4, 36)), walletKeys.P2wshBalanceEntry),
		),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/12, 36)),
				widget.NewButton("P2WSHP2SH", func() {
					generateQRCode("P2WSH-P2SH", walletKeys.P2wshP2shEntry.Text, walletKeys.P2wshP2shHexEntry.Text, appWindow, dodoMoney)
				}),
			),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*5/24, 36)), walletKeys.P2wshP2shEntry),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/24-4, 36)), walletKeys.P2wshP2shBalanceEntry),
		),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/12, 36)),
				widget.NewButton("Ethereum", func() {
					generateQRCode("Ethereum", walletKeys.EthemeumEntry.Text, walletKeys.EthemeumHexEntry.Text, appWindow, dodoMoney)
				}),
			),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth*5/24, 36)), walletKeys.EthemeumEntry),
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/24-4, 36)), walletKeys.EthemeumBalanceEntry),
		),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/3, 150))),
		),

		widget.NewSeparator(),

		container.NewHBox(
			container.New(layout.NewGridWrapLayout(fyne.NewSize(appWidth/3, 36)), exitBtn),
		),
	)

	dodoWalletLayout := container.NewHBox(
		container.NewVScroll(gridLayout),
		widget.NewSeparator(),
		container.NewVScroll(funcLayout),
		widget.NewSeparator(),
		container.NewVScroll(walletLayout),
	)

	appWindow.SetContent(dodoWalletLayout)

	appWindow.Resize(fyne.NewSize(appWidth, appHeight))
	appWindow.SetFixedSize(true)
	appWindow.Show()

	return nil
}

// ================================================================ initialize labels ================================================================
func (c customTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	if name == theme.ColorNameDisabled {
		return color.NRGBA{R: 128, G: 128, B: 128, A: 255}
	}
	return c.Theme.Color(name, variant)
}

func initializeWalletKeys() *EntryLabels {
	keyEntry := func() *widget.Entry {
		entry := widget.NewEntry()
		entry.MultiLine = false
		entry.Disable()

		return entry
	}

	return &EntryLabels{
		MnemonicEntry:            keyEntry(),
		HexEntry:                 keyEntry(),
		TaprootEntry:             keyEntry(),
		TaprootHexEntry:          keyEntry(),
		TaprootBalanceEntry:      keyEntry(),
		LegacyEntry:              keyEntry(),
		LegacyHexEntry:           keyEntry(),
		LegacyBalanceEntry:       keyEntry(),
		P2pkhEntry:               keyEntry(),
		P2pkhHexEntry:            keyEntry(),
		P2pkhBalanceEntry:        keyEntry(),
		NativeSegWitEntry:        keyEntry(),
		NativeSegWitHexEntry:     keyEntry(),
		NativeSegWitBalanceEntry: keyEntry(),
		NestedSegWitEntry:        keyEntry(),
		NestedSegWitHexEntry:     keyEntry(),
		NestedSegWitBalanceEntry: keyEntry(),
		P2shEntry:                keyEntry(),
		P2shHexEntry:             keyEntry(),
		P2shBalanceEntry:         keyEntry(),
		P2wshEntry:               keyEntry(),
		P2wshHexEntry:            keyEntry(),
		P2wshBalanceEntry:        keyEntry(),
		P2wshP2shEntry:           keyEntry(),
		P2wshP2shHexEntry:        keyEntry(),
		P2wshP2shBalanceEntry:    keyEntry(),
		EthemeumEntry:            keyEntry(),
		EthemeumHexEntry:         keyEntry(),
		EthemeumBalanceEntry:     keyEntry(),
	}
}

// initialize hex
func initializeHexInput() *widget.Entry {
	hexInput := widget.NewEntry()
	hexInput.SetPlaceHolder("Please input 64 letters hex.")
	return hexInput
}

// initialize wif
func initializeWifInput() *widget.Entry {
	wifInput := widget.NewEntry()
	wifInput.SetPlaceHolder("please input 52 letters wif.")
	return wifInput
}

// initialize public key
func initializePublicKeyInput() *widget.Entry {
	publicKeyInput := widget.NewEntry()
	publicKeyInput.SetPlaceHolder("Please input 66 letters or 130 letters public key.")
	return publicKeyInput
}

// initialize mnemonic
func initializeMnemonicInput() *widget.Entry {
	mnemonicInput := widget.NewEntry()
	mnemonicInput.SetPlaceHolder("Please input bip39 keywords, if no keywords will be generate random.")
	return mnemonicInput
}

// initialize app
func initializeWindows(min, max string, mnemonicInput, hexInput, wifInput, publicKeyInput, minEntry, maxEntry *widget.Entry, gridSize int, buttons []*widget.Button, gridArray []bool, walletKeys *EntryLabels) {
	// clean
	mnemonicInput.SetText("")
	hexInput.SetText("")
	wifInput.SetText("")
	publicKeyInput.SetText("")
	minEntry.SetText(min)
	maxEntry.SetText(max)

	// initialize gird
	for i := 0; i < gridSize*gridSize; i++ {
		updateGridbySelect(buttons[i], i, gridArray, false)
	}

	// clean KeyLabels Entry
	walletKeys.MnemonicEntry.SetText("")
	walletKeys.HexEntry.SetText("")
	walletKeys.TaprootEntry.SetText("")
	walletKeys.TaprootHexEntry.SetText("")
	walletKeys.TaprootBalanceEntry.SetText("")
	walletKeys.LegacyEntry.SetText("")
	walletKeys.LegacyHexEntry.SetText("")
	walletKeys.LegacyBalanceEntry.SetText("")
	walletKeys.NativeSegWitEntry.SetText("")
	walletKeys.NativeSegWitHexEntry.SetText("")
	walletKeys.NativeSegWitBalanceEntry.SetText("")
	walletKeys.NestedSegWitEntry.SetText("")
	walletKeys.NestedSegWitHexEntry.SetText("")
	walletKeys.NestedSegWitBalanceEntry.SetText("")
	walletKeys.P2pkhEntry.SetText("")
	walletKeys.P2pkhHexEntry.SetText("")
	walletKeys.P2pkhBalanceEntry.SetText("")
	walletKeys.P2shEntry.SetText("")
	walletKeys.P2shHexEntry.SetText("")
	walletKeys.P2shBalanceEntry.SetText("")
	walletKeys.P2wshEntry.SetText("")
	walletKeys.P2wshHexEntry.SetText("")
	walletKeys.P2wshBalanceEntry.SetText("")
	walletKeys.P2wshP2shEntry.SetText("")
	walletKeys.P2wshP2shHexEntry.SetText("")
	walletKeys.P2wshP2shBalanceEntry.SetText("")
	walletKeys.EthemeumEntry.SetText("")
	walletKeys.EthemeumHexEntry.SetText("")
	walletKeys.EthemeumBalanceEntry.SetText("")
}

// ================================================================ Grid ================================================================
func initializeGrid(gridSize int, gridArray []bool) (fyne.CanvasObject, []*widget.Button) {
	width := float32(20)
	height := float32(20)
	grid := container.NewGridWithColumns(gridSize)
	buttons := make([]*widget.Button, gridSize*gridSize)

	for i := 0; i < gridSize*gridSize; i++ {
		i := i
		btn := widget.NewButton("0", nil)

		btn.Resize(fyne.NewSize(width, height))

		btn.OnTapped = func() {
			btnStatus := !gridArray[i]
			updateGridbySelect(btn, i, gridArray, btnStatus)
		}

		grid.Add(btn)
		buttons[i] = btn
	}
	return grid, buttons
}

func updateGridbySelect(btn *widget.Button, index int, gridArray []bool, btnStatus bool) {
	if btnStatus {
		btn.SetText("1")
		gridArray[index] = true
		btn.Importance = widget.HighImportance
	} else {
		btn.SetText("0")
		gridArray[index] = false
		btn.Importance = widget.MediumImportance
	}
	btn.Refresh()
}

func updateGridbyPrivateKey(hexKey *big.Int, gridSize int, buttons []*widget.Button, gridArray []bool) {
	decoded := hexKey.Bytes()

	hexKeyBytes := (gridSize*gridSize + 7) / 8
	if len(decoded) < hexKeyBytes {
		padding := make([]byte, hexKeyBytes-len(decoded))
		decoded = append(padding, decoded...)
	} else if len(decoded) > hexKeyBytes {
		log.Printf("Invalid big.Int key: too many bits for the grid size")
		return
	}

	for i := 0; i < gridSize*gridSize; i++ {
		bit := (decoded[i/8] >> (7 - (i % 8))) & 1
		updateGridbySelect(buttons[i], i, gridArray, bit == 1)
	}
}

func bit2Hex(gridArray []bool) (*big.Int, error) {
	byteArray := make([]byte, (len(gridArray)+7)/8)

	for i, bit := range gridArray {
		if bit {
			byteArray[i/8] |= 1 << (7 - (i % 8))
		}
	}

	privateKeyHex := hex.EncodeToString(byteArray)

	validHex, err := validatePrivateKeyHex(privateKeyHex)
	if err != nil {
		return nil, err
	}

	return validHex, nil
}

func validatePrivateKeyHex(inputKey string) (*big.Int, error) {
	min := new(big.Int)
	max := new(big.Int)
	min.SetString("1", 16)
	max.SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", 16)

	matched, _ := regexp.MatchString("^[0-9a-fA-F]{1,64}$", inputKey)
	if !matched {
		return nil, fmt.Errorf("Invalid key %s\nHex keys only accept hexadecimal strings with a length of 1 to 64 characters.", inputKey)
	}

	privateKey := new(big.Int)
	privateKey.SetString(inputKey, 16)

	if privateKey.Cmp(min) < 0 || privateKey.Cmp(max) > 0 {
		return nil, fmt.Errorf("Hex %s must between %s - %s.", privateKey, min.Text(16), max.Text(16))
	}

	return privateKey, nil
}

// ================================================================ QRCode ================================================================
func generateQRCode(keyType string, entryKey, privateKey string, appWindow fyne.Window, dodoMoney fyne.App) {
	if entryKey == "" {
		dialog.ShowInformation("ERROR", "Not found information to generate QRCode", appWindow)
		return
	}

	qrCodeView := dodoMoney.NewWindow(keyType + " QRCode")
	createQRSection := func(label, keys string) *fyne.Container {
		// fmt.Println(label, keys)
		textEntry := widget.NewEntry()
		textEntry.SetText(keys)
		textEntry.Disable()

		qrImage := canvas.NewImageFromImage(nil)
		qrImage.FillMode = canvas.ImageFillContain
		qrImage.SetMinSize(fyne.NewSize(256, 256))

		qrCode, err := qrcode.New(keys, qrcode.Medium)
		if err != nil {
			log.Printf("Generate QRCode failed: %v", err)
		} else {
			qrImage.Image = qrCode.Image(256)
			qrImage.Refresh()
		}

		saveBtn := widget.NewButton("Save", func() {
			var dirName string
			if keyType == "Mnemonic" {
				dirName = fmt.Sprintf("images/%s", entryKey)
			} else {
				dirName = fmt.Sprintf("images/%s", privateKey)
			}

			if _, err := os.Stat(dirName); os.IsNotExist(err) {
				if err := os.MkdirAll(dirName, 0755); err != nil {
					log.Printf("Create directory failed: %v", err)
				}
			}

			fileName := fmt.Sprintf("%s/%s.png", dirName, label)
			file, err := os.Create(fileName)
			if err != nil {
				log.Printf("Creat file failed: %v", err)
				return
			}
			defer file.Close()

			if err := png.Encode(file, qrCode.Image(256)); err != nil {
				dialog.ShowInformation("FAILED", label+"QRCode save failed.", qrCodeView)
			} else {
				dialog.ShowInformation("SUCCESS", label+"QRCode save success.", qrCodeView)
			}
		})

		return container.NewVBox(
			container.NewHBox(
				container.New(layout.NewGridWrapLayout(fyne.NewSize(45, 36)), widget.NewLabel(label)),
				container.New(layout.NewGridWrapLayout(fyne.NewSize(420, 36)), textEntry),
				container.New(layout.NewGridWrapLayout(fyne.NewSize(45, 36)), saveBtn),
			),
			qrImage,
		)
	}

	var content *fyne.Container
	if keyType == "Mnemonic" {
		content = container.NewVBox(
			createQRSection("Mnemonic", entryKey),
		)
	} else if keyType == "Ethereum" {
		publicKey := privateKey2PublicKey(fmt.Sprintf("%064x", privateKey))
		content = container.NewVBox(
			createQRSection("HEX", privateKey),
			createQRSection("WIF", hex.EncodeToString(publicKey.SerializeCompressed())),
			createQRSection("Addr", entryKey),
		)
	} else if keyType == "Hex Key" {
		wif := generateWifbyPrivateKey(privateKey)
		content = container.NewVBox(
			createQRSection("HEX", privateKey),
			createQRSection("WIF", wif),
		)
	} else if privateKey == "" {
		dialog.ShowInformation("ERROR", "Only support Mnemonic, hex, wif and publickey", appWindow)
		return
	} else {
		wif := generateWifbyPrivateKey(privateKey)
		publicKey := privateKey2PublicKey(fmt.Sprintf("%064x", privateKey))
		content = container.NewVBox(
			createQRSection("HEX", privateKey),
			createQRSection("WIF", wif),
			createQRSection("PubKey", hex.EncodeToString(publicKey.SerializeCompressed())),
			createQRSection("Addr", entryKey),
		)
	}

	exitBtn := widget.NewButton("Exit", func() {
		qrCodeView.Close()
	})

	qrCodeView.SetContent(container.NewVBox(
		content,
		widget.NewSeparator(),
		container.NewGridWithColumns(1, exitBtn),
	))

	qrCodeView.Resize(fyne.NewSize(500, 200))
	qrCodeView.SetFixedSize(true)
	qrCodeView.Show()
}

// ================================================================ Wallet ================================================================
func privateKey2PublicKey(privateKey string) *btcec.PublicKey {
	privateKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		log.Printf("Generate public key failed: %v", err)
	}
	privKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)
	return privKey.PubKey()
}

func generateTaproot(pubKey *btcec.PublicKey, chainParams *chaincfg.Params, walletKeys *EntryLabels, balanceBTCMap map[string]AddressInfo) (string, string) {
	keyTaproot := txscript.ComputeTaprootKeyNoScript(pubKey)
	addrTaproot, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(keyTaproot), chainParams)
	if err != nil {
		log.Printf("Generate Taproot failed: %v", err)
	}
	taproot := addrTaproot.EncodeAddress()
	taprootBalance := matchAddress(taproot, balanceBTCMap)
	walletKeys.TaprootEntry.SetText(taproot)
	walletKeys.TaprootBalanceEntry.SetText(taprootBalance)
	return taproot, taprootBalance
}

func generateLegacy(pubKey *btcec.PublicKey, chainParams *chaincfg.Params, walletKeys *EntryLabels, balanceBTCMap map[string]AddressInfo) (string, string) {
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	addrLegacy, err := btcutil.NewAddressPubKeyHash(pubKeyHash, chainParams)
	if err != nil {
		log.Printf("Generate Legacy failed: %v", err)
	}
	legacy := addrLegacy.EncodeAddress()
	legacyBalance := matchAddress(legacy, balanceBTCMap)
	walletKeys.LegacyEntry.SetText(legacy)
	walletKeys.LegacyBalanceEntry.SetText(legacyBalance)
	return legacy, legacyBalance
}

// 通过 PublicKey 派生 P2PKH(Legacy uncompressed) 地址
func generateP2PKH(pubKey *btcec.PublicKey, chainParams *chaincfg.Params, walletKeys *EntryLabels, balanceBTCMap map[string]AddressInfo) (string, string) {
	pubKeyHash := btcutil.Hash160(pubKey.SerializeUncompressed())
	addrP2PKH, err := btcutil.NewAddressPubKeyHash(pubKeyHash, chainParams)
	if err != nil {
		log.Printf("Generate P2PKH failed: %v", err)
	}
	p2pkh := addrP2PKH.EncodeAddress()
	p2pkhBalance := matchAddress(p2pkh, balanceBTCMap)
	walletKeys.P2pkhEntry.SetText(p2pkh)
	walletKeys.P2pkhBalanceEntry.SetText(p2pkhBalance)
	return p2pkh, p2pkhBalance
}

func generateNestedSegWit(pubKey *btcec.PublicKey, chainParams *chaincfg.Params, walletKeys *EntryLabels, balanceBTCMap map[string]AddressInfo) (string, string) {
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	scriptNested, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddData(pubKeyHash).
		Script()
	if err != nil {
		log.Printf("Generate Nested SegWit script failed: %v", err)
	}
	addrNested, err := btcutil.NewAddressScriptHashFromHash(btcutil.Hash160(scriptNested), chainParams)
	if err != nil {
		log.Printf("Generate Nested SegWit failed: %v", err)
	}
	nested := addrNested.EncodeAddress()
	nestedBalance := matchAddress(nested, balanceBTCMap)
	walletKeys.NestedSegWitEntry.SetText(nested)
	walletKeys.NestedSegWitBalanceEntry.SetText(nestedBalance)
	return nested, nestedBalance
}

func generateNativeSegWit(pubKey *btcec.PublicKey, chainParams *chaincfg.Params, walletKeys *EntryLabels, balanceBTCMap map[string]AddressInfo) (string, string) {
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	addrNative, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, chainParams)
	if err != nil {
		log.Printf("Generate Native SegWit failed: %v", err)
	}
	native := addrNative.EncodeAddress()
	nativeBalance := matchAddress(native, balanceBTCMap)
	walletKeys.NativeSegWitEntry.SetText(native)
	walletKeys.NativeSegWitBalanceEntry.SetText(nativeBalance)
	return native, nativeBalance
}

func generateP2SH(pubKey *btcec.PublicKey, chainParams *chaincfg.Params, walletKeys *EntryLabels, balanceBTCMap map[string]AddressInfo) (string, string) {
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	scriptP2SH, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_DUP).
		AddOp(txscript.OP_HASH160).
		AddData(pubKeyHash).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	if err != nil {
		log.Printf("Generate P2SH script failed: %v", err)
	}
	addrP2SH, err := btcutil.NewAddressScriptHashFromHash(btcutil.Hash160(scriptP2SH), chainParams)
	if err != nil {
		log.Printf("Generate P2SH failed: %v", err)
	}
	p2sh := addrP2SH.EncodeAddress()
	p2shBalance := matchAddress(p2sh, balanceBTCMap)
	walletKeys.P2shEntry.SetText(p2sh)
	walletKeys.P2shBalanceEntry.SetText(p2shBalance)
	return p2sh, p2shBalance
}

func generateP2WSH(pubKey *btcec.PublicKey, chainParams *chaincfg.Params, walletKeys *EntryLabels, balanceBTCMap map[string]AddressInfo) (string, string) {
	pubKeyBytes := pubKey.SerializeCompressed()
	scriptP2WSH, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).
		AddData(pubKeyBytes).
		AddOp(txscript.OP_1).
		AddOp(txscript.OP_CHECKMULTISIG).
		Script()
	if err != nil {
		log.Printf("Generate P2WSH script failed: %v", err)
	}
	witnessProgP2WSH := sha256.Sum256(scriptP2WSH)
	addrP2WSH, err := btcutil.NewAddressWitnessScriptHash(witnessProgP2WSH[:], chainParams)
	if err != nil {
		log.Printf("Generate P2WSH failed: %v", err)
	}
	p2wsh := addrP2WSH.EncodeAddress()
	p2wshBalance := matchAddress(p2wsh, balanceBTCMap)
	walletKeys.P2wshEntry.SetText(p2wsh)
	walletKeys.P2wshBalanceEntry.SetText(p2wshBalance)
	return p2wsh, p2wshBalance
}

func generateP2WSHP2SH(pubKey *btcec.PublicKey, chainParams *chaincfg.Params, walletKeys *EntryLabels, balanceBTCMap map[string]AddressInfo) (string, string) {
	pubKeyBytes := pubKey.SerializeCompressed()
	scriptP2WSH, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).
		AddData(pubKeyBytes).
		AddOp(txscript.OP_1).
		AddOp(txscript.OP_CHECKMULTISIG).
		Script()
	if err != nil {
		log.Printf("Generate P2WSH script failed: %v", err)
	}
	witnessProgP2WSH := sha256.Sum256(scriptP2WSH)
	scriptP2WSHP2SH, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddData(witnessProgP2WSH[:]).
		Script()
	if err != nil {
		log.Printf("Generate P2WSH-P2SH failed: %v", err)
	}
	addrP2WSHP2SH, err := btcutil.NewAddressScriptHash(scriptP2WSHP2SH, chainParams)
	if err != nil {
		log.Printf("Generate P2WSH-P2SH failed: %v", err)
	}
	p2wshp2sh := addrP2WSHP2SH.EncodeAddress()
	p2wshp2shBalance := matchAddress(p2wshp2sh, balanceBTCMap)
	walletKeys.P2wshP2shEntry.SetText(p2wshp2sh)
	walletKeys.P2wshP2shBalanceEntry.SetText(p2wshp2shBalance)
	return p2wshp2sh, p2wshp2shBalance
}

func generateEthereum(pubKey *ecdsa.PublicKey, walletKeys *EntryLabels, balanceETHMap map[string]AddressInfo) (string, string) {
	addrEthereum := crypto.PubkeyToAddress(*pubKey)
	ethereum := strings.ToLower(addrEthereum.Hex())
	ethereumBalance := matchAddress(ethereum, balanceETHMap)
	walletKeys.EthemeumEntry.SetText(ethereum)
	walletKeys.EthemeumBalanceEntry.SetText(ethereumBalance)
	return ethereum, ethereumBalance
}

func generateWalletAddressbyPrivateKey(privateKey *big.Int, walletKeys *EntryLabels, balanceBTCMap, balanceETHMap map[string]AddressInfo, appWindow fyne.Window, dodoMoney fyne.App) {
	if privateKey.Cmp(big.NewInt(0)) == 0 {
		dialog.ShowInformation("ERROR", fmt.Sprintf("PrivateKey(HEX) %s error.", privateKey), appWindow)
		return
	}

	walletKeys.MnemonicEntry.SetText("")
	// walletKeys.BinEntry.SetText(fmt.Sprintf("%0256b", privateKey))
	walletKeys.HexEntry.SetText(fmt.Sprintf("%064x", privateKey))
	publicKey := privateKey2PublicKey(fmt.Sprintf("%064x", privateKey))

	walletKeys.TaprootHexEntry.SetText(fmt.Sprintf("%064x", privateKey))
	taproot, taprootBalance := generateTaproot(publicKey, &chaincfg.MainNetParams, walletKeys, balanceBTCMap)
	if goodLucky(fmt.Sprintf("%064x", privateKey), taproot, taprootBalance, appWindow, dodoMoney) {
		return
	}

	walletKeys.LegacyHexEntry.SetText(fmt.Sprintf("%064x", privateKey))
	legacy, legacyBalance := generateLegacy(publicKey, &chaincfg.MainNetParams, walletKeys, balanceBTCMap)
	if goodLucky(fmt.Sprintf("%064x", privateKey), legacy, legacyBalance, appWindow, dodoMoney) {
		return
	}

	walletKeys.NestedSegWitHexEntry.SetText(fmt.Sprintf("%064x", privateKey))
	nested, nestedBalance := generateNestedSegWit(publicKey, &chaincfg.MainNetParams, walletKeys, balanceBTCMap)
	if goodLucky(fmt.Sprintf("%064x", privateKey), nested, nestedBalance, appWindow, dodoMoney) {
		return
	}

	walletKeys.NativeSegWitHexEntry.SetText(fmt.Sprintf("%064x", privateKey))
	native, nativeBalance := generateNativeSegWit(publicKey, &chaincfg.MainNetParams, walletKeys, balanceBTCMap)
	if goodLucky(fmt.Sprintf("%064x", privateKey), native, nativeBalance, appWindow, dodoMoney) {
		return
	}

	walletKeys.P2pkhHexEntry.SetText(fmt.Sprintf("%064x", privateKey))
	p2pkh, p2pkhBalance := generateP2PKH(publicKey, &chaincfg.MainNetParams, walletKeys, balanceBTCMap)
	if goodLucky(fmt.Sprintf("%064x", privateKey), p2pkh, p2pkhBalance, appWindow, dodoMoney) {
		return
	}

	walletKeys.P2shHexEntry.SetText(fmt.Sprintf("%064x", privateKey))
	p2sh, p2shBalance := generateP2SH(publicKey, &chaincfg.MainNetParams, walletKeys, balanceBTCMap)
	if goodLucky(fmt.Sprintf("%064x", privateKey), p2sh, p2shBalance, appWindow, dodoMoney) {
		return
	}

	walletKeys.P2wshHexEntry.SetText(fmt.Sprintf("%064x", privateKey))
	p2wsh, p2wshBalance := generateP2WSH(publicKey, &chaincfg.MainNetParams, walletKeys, balanceBTCMap)
	if goodLucky(fmt.Sprintf("%064x", privateKey), p2wsh, p2wshBalance, appWindow, dodoMoney) {
		return
	}

	walletKeys.P2wshP2shHexEntry.SetText(fmt.Sprintf("%064x", privateKey))
	p2wshp2sh, p2wshp2shBalance := generateP2WSHP2SH(publicKey, &chaincfg.MainNetParams, walletKeys, balanceBTCMap)
	if goodLucky(fmt.Sprintf("%064x", privateKey), p2wshp2sh, p2wshp2shBalance, appWindow, dodoMoney) {
		return
	}

	walletKeys.EthemeumHexEntry.SetText(fmt.Sprintf("%064x", privateKey))
	ecdsaPubKey := &ecdsa.PublicKey{
		Curve: secp256k1.S256(), // Use secp256k1 curve
		X:     publicKey.X(),
		Y:     publicKey.Y(),
	}
	ethereum, ethereumBalance := generateEthereum(ecdsaPubKey, walletKeys, balanceETHMap)
	if goodLucky(fmt.Sprintf("%064x", privateKey), ethereum, ethereumBalance, appWindow, dodoMoney) {
		return
	}

	// fmt.Printf("%064x\n", privateKey)
}

func generateWalletAddressbyPublicKey(publicKeyHex string, walletKeys *EntryLabels, balanceBTCMap, balanceETHMap map[string]AddressInfo, appWindow fyne.Window, dodoMoney fyne.App) {
	walletKeys.MnemonicEntry.SetText("")
	walletKeys.HexEntry.SetText("")
	walletKeys.TaprootHexEntry.SetText("")
	walletKeys.LegacyHexEntry.SetText("")
	walletKeys.NativeSegWitHexEntry.SetText("")
	walletKeys.NestedSegWitHexEntry.SetText("")
	walletKeys.P2pkhHexEntry.SetText("")
	walletKeys.P2shHexEntry.SetText("")
	walletKeys.P2wshHexEntry.SetText("")
	walletKeys.P2wshP2shHexEntry.SetText("")
	walletKeys.EthemeumHexEntry.SetText("")

	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		log.Printf("Invalid public key: %v", err)
		dialog.ShowInformation("ERROR", fmt.Sprintf("Invalid public key: %s", publicKeyHex), appWindow)
		return
	}

	if len(publicKeyBytes) != 33 && len(publicKeyBytes) != 65 {
		log.Printf("Invalid public key length: %d", len(publicKeyBytes))
		dialog.ShowInformation("ERROR", fmt.Sprintf("Invalid public key length: %d", len(publicKeyBytes)), appWindow)
		return
	}

	publicKey, err := btcec.ParsePubKey(publicKeyBytes)
	if err != nil {
		log.Printf("Parse public key failed: %v", err)
		dialog.ShowInformation("ERROR", fmt.Sprintf("Parse public key failed\n%v", err), appWindow)
		return
	}

	taproot, taprootBalance := generateTaproot(publicKey, &chaincfg.MainNetParams, walletKeys, balanceBTCMap)
	if goodLucky(publicKeyHex, taproot, taprootBalance, appWindow, dodoMoney) {
		return
	}

	legacy, legacyBalance := generateLegacy(publicKey, &chaincfg.MainNetParams, walletKeys, balanceBTCMap)
	if goodLucky(publicKeyHex, legacy, legacyBalance, appWindow, dodoMoney) {
		return
	}

	nested, nestedBalance := generateNestedSegWit(publicKey, &chaincfg.MainNetParams, walletKeys, balanceBTCMap)
	if goodLucky(publicKeyHex, nested, nestedBalance, appWindow, dodoMoney) {
		return
	}

	native, nativeBalance := generateNativeSegWit(publicKey, &chaincfg.MainNetParams, walletKeys, balanceBTCMap)
	if goodLucky(publicKeyHex, native, nativeBalance, appWindow, dodoMoney) {
		return
	}

	p2pkh, p2pkhBalance := generateP2PKH(publicKey, &chaincfg.MainNetParams, walletKeys, balanceBTCMap)
	if goodLucky(publicKeyHex, p2pkh, p2pkhBalance, appWindow, dodoMoney) {
		return
	}

	p2sh, p2shBalance := generateP2SH(publicKey, &chaincfg.MainNetParams, walletKeys, balanceBTCMap)
	if goodLucky(publicKeyHex, p2sh, p2shBalance, appWindow, dodoMoney) {
		return
	}

	p2wsh, p2wshBalance := generateP2WSH(publicKey, &chaincfg.MainNetParams, walletKeys, balanceBTCMap)
	if goodLucky(publicKeyHex, p2wsh, p2wshBalance, appWindow, dodoMoney) {
		return
	}

	p2wshp2sh, p2wshp2shBalance := generateP2WSHP2SH(publicKey, &chaincfg.MainNetParams, walletKeys, balanceBTCMap)
	if goodLucky(publicKeyHex, p2wshp2sh, p2wshp2shBalance, appWindow, dodoMoney) {
		return
	}

	ecdsaPubKey := &ecdsa.PublicKey{
		Curve: secp256k1.S256(), // Use secp256k1 curve
		X:     publicKey.X(),
		Y:     publicKey.Y(),
	}
	ethereum, ethereumBalance := generateEthereum(ecdsaPubKey, walletKeys, balanceETHMap)
	if goodLucky(publicKeyHex, ethereum, ethereumBalance, appWindow, dodoMoney) {
		return
	}
}

func generateRandomKeys(minHex, maxHex string) (*big.Int, error) {
	minKey := new(big.Int)
	maxKey := new(big.Int)

	_, success := minKey.SetString(minHex, 16)
	if !success {
		return nil, fmt.Errorf("Invalid minHex value: %s", minHex)
	}

	_, success = maxKey.SetString(maxHex, 16)
	if !success {
		return nil, fmt.Errorf("Invalid minHex value: %s", maxHex)
	}

	if minKey.Cmp(maxKey) >= 0 {
		return nil, fmt.Errorf("min Hex must be less than max Hex")
	}

	rangeKey := new(big.Int).Sub(maxKey, minKey)
	privateKeyHex, err := rand.Int(rand.Reader, rangeKey)
	if err != nil {
		log.Printf("Generate privateKey failed: %v", err)
	}

	privateKeyHex.Add(privateKeyHex, minKey)

	return privateKeyHex, nil
}

func matchAddress(address string, balanceMap map[string]AddressInfo) string {
	if addrInfo, found := balanceMap[address]; found {
		return addrInfo.Balance
	}
	return "0"
}

func goodLucky(key, address, balance string, appWindow fyne.Window, dodoMoney fyne.App) bool {
	if balance != "0" {
		copyButton := widget.NewButton("Copy", func() {
			walletInfo := fmt.Sprintf("%s | %s | %s\n", key, address, balance)

			clipboard := appWindow.Clipboard()
			clipboard.SetContent(walletInfo)

			dialog.ShowInformation("SUCCESSED", "Copy success！", appWindow)
		})

		saveButton := widget.NewButton("Save", func() {
			fileName := "data/bonus.txt"
			dir := filepath.Dir(fileName)
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				if err := os.MkdirAll(dir, 0755); err != nil {
					log.Printf("Create directory %s failed: %v", dir, err)
				}
			}

			file, err := os.OpenFile(fileName, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
			if err != nil {
				log.Printf("Create file %s failed: %v", fileName, err)
			}
			defer file.Close()

			_, err = fmt.Fprintf(file, "%s | %s | %s\n", key, address, balance)
			if err != nil {
				dialog.ShowInformation("FAILED", fmt.Sprintf("Wallet save failed: %s", err.Error()), appWindow)
				return
			} else {
				dialog.ShowInformation("SUCCESSED", "Wallet save success！", appWindow)
				return
			}
		})

		var explorerURL string
		if strings.HasPrefix(address, "0x") {
			explorerURL = fmt.Sprintf("https://www.blockchain.com/explorer/addresses/eth/%s", address)
		} else if strings.HasPrefix(address, "1") || strings.HasPrefix(address, "3") || strings.HasPrefix(address, "bc1") {
			explorerURL = fmt.Sprintf("https://www.blockchain.com/explorer/addresses/btc/%s", address)
		}

		parsedURL, err := url.Parse(explorerURL)
		if err != nil {
			fyne.LogError("Parse URL failed", err)
			return false
		}

		addressLink := widget.NewHyperlink("Blockchain", parsedURL)

		privateKeyLabel := widget.NewLabel(fmt.Sprintf("hex:  %s", key))
		addressLabel := widget.NewLabel(fmt.Sprintf("address:  %s", address))

		privateKeyRow := container.NewHBox(
			privateKeyLabel,
			copyButton,
		)

		addressRow := container.NewHBox(
			addressLabel,
			addressLink,
		)

		balanceRow := container.NewHBox(
			widget.NewLabel(fmt.Sprintf("balance:  %s", balance)),
			saveButton,
		)

		content := container.NewVBox(
			privateKeyRow,
			addressRow,
			balanceRow,
		)

		dialog.ShowCustom("Lucky Win", "Exit", content, appWindow)

		fileName := "data/bonus.txt"
		dir := filepath.Dir(fileName)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0755); err != nil {
				log.Printf("Create directory %s failed: %v", dir, err)
			}
		}

		file, err := os.OpenFile(fileName, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			log.Printf("Create file %s failed %v", fileName, err)
		}
		defer file.Close()

		_, err = fmt.Fprintf(file, "%s | %s | %s\n", key, address, balance)
		if err != nil {
			dodoMoney.SendNotification(fyne.NewNotification("FAILED", fmt.Sprintf("%s save failed!\nClick Copy butten save the wallte", address)))
		} else {
			dodoMoney.SendNotification(fyne.NewNotification("SUCCESS", fmt.Sprintf("hex %s\n balance %s\nsave success!", key, balance)))
		}

		return true
	}
	return false
}

func generateMnemonic(keywords []string, mnLength int) string {
	// 12: {EntropyBits: 128, ChecksumBits: 4, TotalBits: 132}
	// 15: {EntropyBits: 160, ChecksumBits: 5, TotalBits: 165}
	// 18: {EntropyBits: 192, ChecksumBits: 6, TotalBits: 198}
	// 21: {EntropyBits: 224, ChecksumBits: 7, TotalBits: 231}
	// 24: {EntropyBits: 256, ChecksumBits: 8, TotalBits: 264}
	entropyMap := map[int]int{
		12: 128,
		15: 160,
		18: 192,
		21: 224,
		24: 256,
	}
	entropyBits, ok := entropyMap[mnLength]
	if !ok {
		log.Printf("unsupport length: %d", mnLength)
		return ""
	}

	customEntropy := make([]byte, entropyBits/8)

	for i, word := range keywords {
		index := indexOf(word, bip39.GetWordList())
		if index < 0 {
			log.Printf("Keywords [%s] not in BIP39 list.", word)
			return ""
		}
		for j := 0; j < 11; j++ {
			if index&(1<<(10-j)) != 0 {
				byteIndex := (i*11 + j) / 8
				bitIndex := (i*11 + j) % 8
				customEntropy[byteIndex] |= 1 << (7 - bitIndex)
			}
		}
	}

	remainingBits := 8 - len(keywords)*11%8
	usedBytes := (len(keywords)*11 + remainingBits) / 8
	for i := usedBytes; i < len(customEntropy); i++ {
		randomByte, err := generateRandomByte()
		if err != nil {
			log.Printf("Generate failed: %v", err)
			return ""
		}
		customEntropy[i] = randomByte
	}

	mnemonic, err := bip39.NewMnemonic(customEntropy)
	if err != nil {
		log.Printf("Generate mnemonic failed: %v", err)
		return ""
	}

	if !bip39.IsMnemonicValid(mnemonic) {
		log.Printf("%d mnemonic: [ %s ] check failed", mnLength, mnemonic)
	}

	return mnemonic
}

func generateRandomByte() (byte, error) {
	randomInt, err := rand.Int(rand.Reader, big.NewInt(256))
	if err != nil {
		return 0, err
	}
	return byte(randomInt.Int64()), nil
}

// 查找单词在单词表中的索引
func indexOf(word string, wordList []string) int {
	for i, w := range wordList {
		if w == word {
			return i
		}
	}
	return -1
}

func generateWalletByMnemonic(mnemonic string, walletKeys *EntryLabels, balanceBTCMap, balanceETHMap map[string]AddressInfo, appWindow fyne.Window, dodoMoney fyne.App) {
	seed := bip39.NewSeed(mnemonic, "")

	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		log.Printf("无法创建主密钥: %v", err)
	}

	walletKeys.MnemonicEntry.SetText(mnemonic)

	taprootPrivateKey := generateHexByMasterKey(masterKey, "m/86'/0'/0'/0/0")
	taprootPublicKey := privateKey2PublicKey(fmt.Sprintf("%064x", taprootPrivateKey))
	walletKeys.TaprootHexEntry.SetText(fmt.Sprintf("%064x", taprootPrivateKey))
	taproot, taprootBalance := generateTaproot(taprootPublicKey, &chaincfg.MainNetParams, walletKeys, balanceBTCMap)
	if goodLucky(fmt.Sprintf("%064x", taprootPrivateKey), taproot, taprootBalance, appWindow, dodoMoney) {
		return
	}

	legacyPrivateKey := generateHexByMasterKey(masterKey, "m/44'/0'/0'/0/0")
	legacyPublicKey := privateKey2PublicKey(fmt.Sprintf("%064x", legacyPrivateKey))
	walletKeys.LegacyHexEntry.SetText(fmt.Sprintf("%064x", legacyPrivateKey))
	legacy, legacyBalance := generateLegacy(legacyPublicKey, &chaincfg.MainNetParams, walletKeys, balanceBTCMap)
	if goodLucky(fmt.Sprintf("%064x", legacyPrivateKey), legacy, legacyBalance, appWindow, dodoMoney) {
		return
	}

	nestedPrivateKey := generateHexByMasterKey(masterKey, "m/49'/0'/0'/0/0")
	nestedPublicKey := privateKey2PublicKey(fmt.Sprintf("%064x", nestedPrivateKey))
	walletKeys.NestedSegWitHexEntry.SetText(fmt.Sprintf("%064x", nestedPrivateKey))
	nested, nestedBalance := generateNestedSegWit(nestedPublicKey, &chaincfg.MainNetParams, walletKeys, balanceBTCMap)
	if goodLucky(fmt.Sprintf("%064x", nestedPrivateKey), nested, nestedBalance, appWindow, dodoMoney) {
		return
	}

	nativePrivateKey := generateHexByMasterKey(masterKey, "m/84'/0'/0'/0/0")
	nativePublicKey := privateKey2PublicKey(fmt.Sprintf("%064x", nativePrivateKey))
	walletKeys.NativeSegWitHexEntry.SetText(fmt.Sprintf("%064x", nativePrivateKey))
	native, nativeBalance := generateNativeSegWit(nativePublicKey, &chaincfg.MainNetParams, walletKeys, balanceBTCMap)
	if goodLucky(fmt.Sprintf("%064x", nativePrivateKey), native, nativeBalance, appWindow, dodoMoney) {
		return
	}

	ethereumPrivateKey := generateHexByMasterKey(masterKey, "m/44'/60'/0'/0/0")
	ethereumPublicKey := privateKey2PublicKey(fmt.Sprintf("%064x", ethereumPrivateKey))
	walletKeys.EthemeumHexEntry.SetText(fmt.Sprintf("%064x", ethereumPrivateKey))
	ecdsaPubKey := &ecdsa.PublicKey{
		Curve: secp256k1.S256(), // Use secp256k1 curve
		X:     ethereumPublicKey.X(),
		Y:     ethereumPublicKey.Y(),
	}
	ethereum, ethereumBalance := generateEthereum(ecdsaPubKey, walletKeys, balanceETHMap)
	if goodLucky(fmt.Sprintf("%064x", ethereumPrivateKey), ethereum, ethereumBalance, appWindow, dodoMoney) {
		return
	}
}

func generateHexByMasterKey(masterKey *hdkeychain.ExtendedKey, derivationPath string) *big.Int {
	pathSegments, err := parseDerivationPath(derivationPath)
	if err != nil {
		log.Fatalf("%v", err)
	}

	childKey := masterKey
	for _, segment := range pathSegments {
		childKey, err = childKey.Derive(segment)
		if err != nil {
			log.Fatalf("%v", err)
		}
	}

	priKey, err := childKey.ECPrivKey()
	if err != nil {
		log.Fatalf("%v", err)
	}
	hexKey := new(big.Int).SetBytes(priKey.Serialize())

	return hexKey
}

func parseDerivationPath(path string) ([]uint32, error) {
	var segments []uint32
	var hardened uint32 = hdkeychain.HardenedKeyStart

	for _, segment := range strings.Split(path, "/") {
		if segment == "m" {
			continue
		}
		if segment[len(segment)-1] == '\'' {
			value, err := strconv.Atoi(segment[:len(segment)-1])
			if err != nil {
				log.Fatalf("%v", err)
			}
			segments = append(segments, uint32(value)+hardened)
		} else {
			value, err := strconv.Atoi(segment)
			if err != nil {
				log.Fatalf("%v", err)
			}
			segments = append(segments, uint32(value))
		}
	}
	return segments, nil
}

func generatePrivateKeybyWif(wif string) (*big.Int, error) {
	decoded := base58.Decode(wif)

	if len(decoded) == 0 {
		return nil, fmt.Errorf("Invaild WIF")
	} else if len(decoded) < 37 {
		return nil, fmt.Errorf("Invaild decode WIF: %d", len(decoded))
	}

	wifChecksum := decoded[len(decoded)-4:]
	data := decoded[:len(decoded)-4]

	hash1 := sha256.Sum256(data)
	hash2 := sha256.Sum256(hash1[:])
	calChecksum := hash2[:4]

	if len(wifChecksum) != len(calChecksum) {
		return nil, fmt.Errorf("WIF checksum failecd")
	}
	for i := 0; i < len(wifChecksum); i++ {
		if wifChecksum[i] != calChecksum[i] {
			return nil, fmt.Errorf("WIF checksum failecd")
		}
	}

	privateKey := data[1:]
	if len(privateKey) == 33 && privateKey[32] == 0x01 {
		privateKey = privateKey[:32]
	}

	hexKey := new(big.Int).SetBytes(privateKey)
	return hexKey, nil
}

func generateWifbyPrivateKey(privateKey string) string {
	customPrivateKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		log.Printf("Generate WIF failed: %v", err)
	}
	privateKeyHex, _ := btcec.PrivKeyFromBytes(customPrivateKeyBytes)

	wif, err := btcutil.NewWIF(privateKeyHex, &chaincfg.MainNetParams, true)
	if err != nil {
		log.Printf("Generate WIF failed: %v", err)
	}
	return wif.String()
}
