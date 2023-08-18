package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ORPHAN_DELTA  = 300
	MAX_POW_COUNT = 1000
	DIFFICULTY    = "00"

	debug_mode = false
)

// ブロックの定義
type Block struct {
	Hight     int      `json:"hight"`
	Prev      string   `json:"prev"`
	Hash      string   `json:"hash"`
	Nonce     string   `json:"nonce"`
	PowCount  int      `json:"powcount"`
	Data      string   `json:"data"`
	Timestamp int64    `json:"timestamp"`
	Child     []*Block // このブロックの子ブロックが入る。分岐が解消されるまではここに以降のブロックが入る
	Sibling   []*Block // 同じ親を持つブロック。兄弟ブロックで、この中の１つのみが最終的に残る
}

// ブロックチェーン管理構造体
type BlockChain struct {
	Info           string
	initialized    bool
	mining         bool
	blocks         []*Block
	last_block     int
	fix_block      int
	orphan_blocks  []*Block
	invalid_blocks []*Block
	retry_blocks   []*Block
	mu             sync.Mutex
}

// Hash計算
func (b *Block) calcHash() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%d%s%s%d%s%d", b.Hight, b.Prev, b.Nonce, b.PowCount, b.Data, b.Timestamp))))
}

// Hash計算してブロックに設定
func (b *Block) hash() string {
	b.Hash = b.calcHash()
	return b.Hash
}

// ブロック検証
func (b *Block) isValid() bool {

	if debug_mode {
		fmt.Println("Hash = ", b.Hash)
		fmt.Println("cal Hash = ", b.calcHash())
	}

	if b.Hash != b.calcHash() {
		return false
	}
	return true
}

// マイニング中か判断
func (bc *BlockChain) IsMining() bool {
	return bc.mining
}

// ブロックチェーン管理構造の初期化
func (bc *BlockChain) Init(first bool) (*BlockChain, error) {
	fmt.Println("Block_init")
	bc.blocks = make([]*Block, 0)
	bc.orphan_blocks = make([]*Block, 0)
	bc.invalid_blocks = make([]*Block, 0)
	bc.retry_blocks = make([]*Block, 0)
	bc.initialized = true
	bc.mining = false
	bc.Info = "My Block Chain Ver0.1"

	if first {
		// genesisブロック
		genesis_block := new(Block)
		genesis_block.Timestamp = 0
		genesis_block.Hight = 0
		genesis_block.Data = "Genesis Block"
		genesis_block.hash()
		bc.blocks = append(bc.blocks, genesis_block)
	}

	return bc, nil
}

// 初期化完了し動作可能とする
func (bc *BlockChain) Initialized() error {
	bc.initialized = true
	return nil
}

// データ保存リクエスト
func (bc *BlockChain) SaveData(data string) bool {

	fmt.Println("SaveData:", data)
	fmt.Println("マークルパスを保存")
	merkle := bc.GETmarclepass()
	//merkle := "sadjghasd"
	err := Check_Broadcast(merkle)
	if err == false {
		fmt.Println("Check_Broadcast error:", err)
		return false
	}
	// 自身のマイニング
	go bc.MiningBlock([]byte(data), true)
	return true
}

// マイニング処理
func (bc *BlockChain) MiningBlock(data []byte, primary bool) error {
	if debug_mode {
		fmt.Println("MiningBlock:", data)
	}
	bc.mu.Lock()
	if bc.initialized == false {
		bc.mu.Unlock()
		fmt.Println("Could not start mining.")
		return errors.New("Could not start mining.")
	}
	if bc.mining {
		bc.mu.Unlock()
		fmt.Println("Someone Mining.")
		return errors.New("Someone Mining.")
	}
	bc.mining = true
	bc.mu.Unlock()

	// ブロックに記録するデータ取り出し
	d := data

	// マイニング
	block, err := bc.Create(string(d), true, primary)
	b, _ := json.Marshal(block)
	if err == nil {
		if debug_mode {
			fmt.Println(block)
		}
		// 全ノードに保存要求を送る
		//Broadcast("/newblock",block, false)
		fmt.Println("全ノードに保存要求を送る")
		fmt.Println("bを表示")
		fmt.Println(b)
		Block_Broadcast("/accept", b, false)
	}

	bc.mu.Lock()
	bc.mining = false
	bc.mu.Unlock()
	return err
}

// 新しいブロックの承認＆追加アクション
func (bc *BlockChain) NewBlock(msg []byte) error {
	fmt.Println("new block action")
	fmt.Println(msg)
	block := new(Block)
	err := json.Unmarshal(msg, block)
	if err != nil {
		fmt.Println("Invalid Block.", err)
		return errors.New("Invalid Block.")
	}
	fmt.Println(block)
	//     fmt.Println(msg)
	//     fmt.Println(string(msg))
	if debug_mode {
		fmt.Println("block = ", block)
	}

	// Check
	if block.isValid() == false {
		/* 不正なブロックなのでつながない */
		return errors.New("Invalid Block: ID=" + strconv.FormatInt(int64(block.Hight), 10))
	}

	// チェーンにつなぐ
	bc.AddBlock(block)

	return nil
}

// ブロックをつなぐ
func (bc *BlockChain) AddBlock(block *Block) error {

	if debug_mode {
		fmt.Println("AddBlock:", block)
	}

	// ロック
	bc.mu.Lock()

	// ブロックをチェーンにつなぐ
	err := bc.blockAppendSimple(block)
	if err != nil {
		// アンロック
		bc.mu.Unlock()
		return err
	}

	// orphan_blocksに繋がっているものの親が繋がったか確認する
	last_block := bc.blocks[len(bc.blocks)-1]
	for i, b := range bc.orphan_blocks {
		if b.Prev == last_block.Hash {
			if debug_mode {
				fmt.Println("retry")
				fmt.Println("list block before")
				bc.DumpChain()
			}

			// orphan_blocksから外す
			bc.orphan_blocks = append(bc.orphan_blocks[:i], bc.orphan_blocks[i+1:]...)

			// ブロックをチェーンにつなぐ
			bc.blockAppendSimple(b)
			if debug_mode {
				fmt.Println(b)
				fmt.Println("list block after")
				bc.DumpChain()
			}
		}
	}

	// アンロック
	bc.mu.Unlock()

	return nil
}

// ブロック一覧を取得
func (bc *BlockChain) ListBlock() []*Block {
	fmt.Println("ListBlock:")
	fmt.Println("  blocks->")
	bc.mu.Lock()
	for _, b := range bc.blocks {
		fmt.Println("    ", b.Data)
	}
	fmt.Println("  orphan_blocks->")
	for _, b := range bc.orphan_blocks {
		fmt.Println("    ", b.Data)
	}
	fmt.Println("----------")
	bc.mu.Unlock()
	return bc.blocks
}

/***** デバッグ用 *******/
func (bc *BlockChain) DumpChain() {
	fmt.Println("----------------")
	fmt.Println("Info => ", bc.Info)

	fmt.Println("ListBlock:")
	fmt.Println("  blocks->")
	for _, b := range bc.blocks {
		//fmt.Println("    ", b)
		fmt.Println("    ", b.Data)
	}
	fmt.Println("  orphan_blocks->")
	for _, b := range bc.orphan_blocks {
		//fmt.Println("    ", b)
		fmt.Println("    ", b.Data)
	}
	fmt.Println("----------------")
	return
}

// ブロックをチェーンにつなぐ
func (bc *BlockChain) blockAppendSimple(block *Block) error {
	if debug_mode {
		fmt.Println("blockAppendSimple:", block)
	}
	// チェーンの最後
	last_block := bc.blocks[len(bc.blocks)-1]
	// Blockの親がblocksの最後か？
	if block.Prev == last_block.Hash {
		// つなぐ
		bc.blocks = append(bc.blocks, block)
	} else if last_block.Prev == block.Prev {
		if last_block.Timestamp > block.Timestamp {
			// 入れ替え＆last_block解放
			bc.blocks[len(bc.blocks)-1] = block
			fmt.Println("Purge Block:", last_block)
		}
	} else if block.Hight > last_block.Hight {
		// 親がいなければorphanにつなぐ
		bc.orphan_blocks = append(bc.orphan_blocks, block)

		// 隙間があったら、間のブロックの送信を依頼
		for i := last_block.Hight + 1; i < block.Hight; i++ {
			/* 隙間のブロックを要求 */
			bc.RequestBlock(i)
			time.Sleep(1 * time.Second / 2)
		}
	} else {
		// それ以外がチェーンに繋げないので破棄
		fmt.Println("Purge Block:", block)
	}

	return nil

}

// ブロックを要求
func (bc *BlockChain) RequestBlock(id int) error {
	fmt.Println("RequestBlock:", id)
	bid := make([]byte, 4)
	binary.LittleEndian.PutUint32(bid, uint32(id))

	//bc.p2p.SendOne(P2P.CMD_SENDBLOCK, s_msg)
	return nil
}

// ブロック作成(マイニング)
func (bc *BlockChain) Create(data string, pow bool, primary bool) (*Block, error) {

	if debug_mode {
		fmt.Println("Create:", data)
	}

	block := new(Block)
	block.Child = make([]*Block, 0)
	block.Sibling = make([]*Block, 0)

	// 競合、フォークを解消するために、一番長いチェーンの後につなげるようにする
	last_block := bc.getPrevBlock()

	// ブロックの中身を詰める
	block.Prev = last_block.Hash
	block.Timestamp = time.Now().UnixNano()
	block.Data = data
	block.Hight = last_block.Hight + 1

	// PoW
	if pow {
		/*
			Nonceを変えながら、条件を満たすハッシュを計算するループを回す。
			実験では、あまり終わらないと大変なので、100回(100秒)やってだめなら、とりえず進むことにする。
		*/
		for i := 0; i < MAX_POW_COUNT; i++ {
			block.Nonce = fmt.Sprintf("%x", rand.New(rand.NewSource(block.Timestamp/int64(i+1))))
			block.PowCount = i
			block.hash()
			if debug_mode {
				fmt.Println("Try ", i, block)
			} else {
				fmt.Println("Try ", i, block.Hash)
			}
			// 求めたハッシュが条件を満たすか確認する
			if strings.HasPrefix(block.Hash, DIFFICULTY) {
				fmt.Println("Found!!")
				break
			}

		}
		if primary == false && !strings.HasPrefix(block.Hash, DIFFICULTY) {
			return nil, errors.New("Failed to Mine.")
		}
	} else {
		block.hash()
	}

	return block, nil
}

// チェーンの親ブロックを見つける
func (bc *BlockChain) getPrevBlock() *Block {

	// 一番長いチェーンから親を決める
	// ロック
	bc.mu.Lock()

	last_block := bc.blocks[len(bc.blocks)-1]

	block := last_block
	if len(last_block.Sibling) > 0 {
		for _, b := range last_block.Sibling {
			if len(block.Child) < len(b.Child) {
				block = b
			}
		}
	}

	// アンロック
	bc.mu.Unlock()

	return block
}

// マークルパスの計算
func (bc *BlockChain) GETmarclepass() string {
	var marcle []string
	var temp []string
	fmt.Println("ブロック一覧を取得")
	for _, b := range bc.blocks {
		marcle = append(marcle, b.Hash)
	}
	//ブロック数が奇数であれば最後のハッシュ値をもう一度追加
	if len(marcle)%2 != 0 {
		marcle = append(marcle, marcle[len(marcle)-1])
	}
	for len(marcle) > 1 {
		for i := 0; i < len(marcle); i += 2 {
			hash := sha256.Sum256([]byte(marcle[i] + marcle[i+1]))
			temp = append(temp, fmt.Sprintf("%x", hash))
		}
		marcle = temp
		temp = nil // 'temp' スライスをリセット
	}
	return marcle[0]
}
