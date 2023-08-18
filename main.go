package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

const (
	HOST            = "127.0.0.1"
	API_PORT        = 3000
	INIT            = "/init/"
	BLOCKLIST       = "/blocks"
	BLOCK           = "/block/"
	NODELIST        = "/nodes"
	NODE            = "/node/"
	MALICIOUS_BLOCK = "/malicious_block/"
	CHECK           = "/check/"
)

var (
	p2p *P2PNetwork
	bc  *BlockChain
)

// サーバ管理の構造体
type Node struct {
	Host string   `json:"host" form:"host" query:"host"`
	Self bool     `json:"-"`
	Conn net.Conn `json:"-"`
}

type P2PNetwork struct {
	nodes []*Node
}

// ブロック一覧取得
func listBlocks(c echo.Context) error {
	fmt.Println("listBlocks:")
	blocks := bc.ListBlock()
	return c.JSON(http.StatusOK, blocks)
}
func returnerr(c echo.Context) error {
	return c.String(http.StatusOK, "ブロックの生成が拒否されました")
}
func testdeb(c echo.Context) error {
	fmt.Println("test debug  ・・・OK")
	return c.String(http.StatusOK, "My Block Chain Ver0.1")
}
func send(s_node string, cmd string) error {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	// クライアントの作成
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	url := s_node + cmd
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		log.Fatal(err)
	}
	// リクエストの送信
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	fmt.Println("send func done")
	return nil
}
func testsend(c echo.Context) error {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	// クライアントの作成
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	// リクエストの作成
	url := "https://127.0.0.1:3001/"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}

	// リクエストの送信
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	return c.String(http.StatusOK, "送信完了")
}

func Broadcast(endpoint string, param string, self bool) error {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	for _, n := range p2p.nodes {
		if n.Self && self {
			fmt.Println("not sent")
			continue
		}

		fmt.Println(n.Host)
		url := "https://" + n.Host + endpoint
		if param != "" {
			url += "/" + param
		}
		req, err := http.NewRequest("POST", url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
	}
	return nil
}

// サーバ追加アクション
func addsrv(c echo.Context) error {
	ip := c.Param("host")
	fmt.Println("addNode:", ip)

	node := &Node{
		Host: ip,
		Self: false,
		// 他のフィールドを初期化する必要があれば追加する
	}
	// P2Pネットワークのインスタンスを作成
	fmt.Println("追加前")
	fmt.Println(p2p.nodes)
	// 自身のノードリストに追加サーバ情報を登録
	p2p.nodes = append(p2p.nodes, node)
	fmt.Println("追加後")
	fmt.Println(p2p.nodes)

	//今持っている他のサーバ情報を新規ノードに送信
	for _, n := range p2p.nodes {
		fmt.Println("新規サーバノード追加要求")
		if ip == n.Host {
			fmt.Println("not sent")
			continue
		}
		// リクエストの作成
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}
		url := "https://" + ip + "/addonly/" + n.Host
		fmt.Println("urlの中身：" + url)
		req, err := http.NewRequest("POST", url, nil)
		if err != nil {
			log.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()

	}
	// 他のサーバにも新しく追加されたサーバ情報を共有
	for _, n := range p2p.nodes {
		if n.Self || ip == n.Host {
			fmt.Println("not sent")
			continue
		} else {
			fmt.Println("サーバ追加要求")
			fmt.Println(n.Host)
			// リクエストの作成
			tlsConfig := &tls.Config{
				InsecureSkipVerify: true,
			}
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: tlsConfig,
				},
			}
			url := "https://" + n.Host + "/addonly/" + ip
			fmt.Println("urlの中身：" + url)
			req, err := http.NewRequest("POST", url, nil)
			if err != nil {
				log.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				log.Fatal(err)
			}
			defer resp.Body.Close()
			return c.String(http.StatusOK, "送信完了:"+n.Host)
			// elseブロックの処理を記述する
		}
	}

	return c.String(http.StatusOK, "新規接続完了")
}

func add(c echo.Context) error {
	ip := c.Param("host")
	node := &Node{
		Host: ip,
		Self: false,
		// 他のフィールドを初期化する必要があれば追加する
	}
	p2p.nodes = append(p2p.nodes, node)
	fmt.Println("追加要求受信" + ip)
	fmt.Println(p2p.nodes)
	return c.String(http.StatusOK, "接続完了")
}

// ブロックに記録するデータを渡し、ブロック作成を依頼する
func createBlock(c echo.Context) error {
	fmt.Println("createBlock:")
	data := c.FormValue("pass")
	fmt.Println("data表示：" + data)

	if bc.IsMining() {
		// マイニングは同時実行しない
		return echo.NewHTTPError(http.StatusConflict, "Already Mining")
	}

	// データ保存処理
	ans := bc.SaveData(data)
	if ans == false {
		return c.String(http.StatusOK, "ブロックの生成が拒否されました")
	}

	return c.NoContent(http.StatusOK)
}

// ノードのマイニングアクション
func node_mining(c echo.Context) error {
	req := c.Request()
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("mainingdataを表示")
	fmt.Println(bodyBytes)
	bc.MiningBlock(bodyBytes, true)
	return nil
}

func Block_Broadcast(endpoint string, b []byte, self bool) error {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	for _, n := range p2p.nodes {
		if n.Self && self {
			fmt.Println("not sent")
			continue
		}
		buf := bytes.NewBuffer(b)
		//fmt.Println("bufを表示")
		//fmt.Println(buf)
		fmt.Println(n.Host)
		url := "https://" + n.Host + endpoint
		req, err := http.NewRequest("POST", url, buf)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
	}
	return nil
}

func Check_Broadcast(b string) bool {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 3 * time.Second, // ここでタイムアウトを設定します
	}
	responses := make([]string, len(p2p.nodes))
	fmt.Println("レスポンス初期化完了")
	fmt.Println(responses)
	fmt.Println("bを表示")
	fmt.Println(b)

	var errs []error

	for i, n := range p2p.nodes {
		if n.Self {
			fmt.Println("not sent", n.Host)
			continue
		}
		buf := bytes.NewBuffer([]byte(b))
		fmt.Println(n.Host)
		url := "https://" + n.Host + "/markle_check"
		req, err := http.NewRequest("POST", url, buf)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			errs = append(errs, fmt.Errorf("レスポンス読み込みエラー（サーバ %d）: %v", i+1, err))
			continue
		}

		// レスポンスを配列に格納
		fmt.Println(i)
		responses[i-1] = string(body)
	}

	fmt.Println("サーバからの返信")
	fmt.Println(responses)

	count := 0
	for _, response := range responses {
		if response == "E" {
			count++
		}
	}
	if count >= len(p2p.nodes)/2 {
		return false
	}

	return true
}

func check_markle(c echo.Context) error {
	marcle := bc.GETmarclepass()
	req := c.Request()
	bodyBytes, _ := io.ReadAll(req.Body)
	if string(bodyBytes) == marcle {
		// マークルパスが一致した場合の処理
		fmt.Println("マークルパスが一致しました")
		return nil
	}

	// マークルパスが一致しなかった場合の処理
	fmt.Println("マークルパスが一致しません")
	return c.String(http.StatusOK, "E")
}

func Node_block(c echo.Context) error {
	req := c.Request()
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("受け取ったbodyBytesを表示")
	fmt.Println(bodyBytes)
	bc.NewBlock(bodyBytes)
	return c.String(http.StatusOK, "ブロックの処理が成功しました")
}

func check_pass(c echo.Context) error {
	data := c.FormValue("pass")
	fmt.Println(data)
	//マークルを作成して全体に送信
	//marcle := bc.GETmarclepass()
	marcle := "dammymarclepass"
	if Check_Broadcast(marcle) {
		for _, n := range bc.blocks {
			if n.Data == data {
				fmt.Println("認証が成功しました")
				return c.String(http.StatusOK, "成功")
			}
		}
		// ブロックを全てチェックしても認証が成功しなかった場合はここで失敗を返す
		fmt.Println("認証に失敗しました")
		return c.String(http.StatusOK, "失敗")
	}
	// Check_Broadcastがfalseの場合も考慮する必要があります
	return c.String(http.StatusInternalServerError, "認証エラー")
}

func main() {
	apiport := flag.Int("apiport", API_PORT, "API port number")
	host := flag.String("host", HOST, "p2p port number")
	flag.Parse()

	api_port := uint16(*apiport)
	my_host := *host
	myip := my_host + ":" + strconv.Itoa(*apiport)
	fmt.Println("MyNODE:", myip)
	fmt.Println("HOST:", my_host)
	fmt.Println("API port:", api_port)
	bc = new(BlockChain)
	//p2pノードリスト作成 初期化を行う
	mynode := &Node{
		Host: myip,
		Self: true,
		// 他のフィールドを初期化する必要があれば追加する
	}
	p2p = &P2PNetwork{}
	p2p.nodes = append(p2p.nodes, mynode)

	//ブロックチェーンの初期化
	_, err := bc.Init(true) // 本当は１つ目のサーバのみtrueで他のものはfalse、そしてgenesisブロックも転送が必要
	if err == nil {
		fmt.Println("Block Chain module initialized.")
	} else {
		fmt.Println(err)
		return
	}

	if debug_mode {
		fmt.Println(bc)
	}

	// Echoセットアップ
	e := echo.New()

	e.Use(middleware.Recover())
	e.Use(middleware.Logger())
	e.Use(middleware.Secure())

	// ブラウザからjavascriptを使ってAPI呼び出しできるようにCORS対応
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{echo.GET, echo.PUT, echo.POST, echo.DELETE, echo.HEAD},
	}))

	e.GET("/", testdeb)
	e.GET("/send", testsend)
	e.GET("/addnode/"+":host", addsrv)
	e.POST("/addonly/"+":host", add)
	e.POST("/block", createBlock)
	e.POST("/accept", Node_block)
	e.POST("/minning", node_mining)
	e.GET("/blocks", listBlocks)
	e.POST("/markle_check", check_markle)
	e.POST("/pass_check", check_pass)
	// TLS証明書のパス
	certFile := "C:/Users/2018041/Desktop/pychain/certificate.pem"
	keyFile := "C:/Users/2018041/Desktop/pychain/private_key.pem"

	// サーバーの設定と起動
	e.Server.TLSConfig = &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12, // TLSのバージョンを指定
		// その他の設定を追加できます
	}
	e.Logger.Fatal(e.StartTLS(my_host+":"+strconv.Itoa(int(api_port)), certFile, keyFile))

}
