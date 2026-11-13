// dbdump 诊断工具：列出资产库里的任务与资产分布
package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

func main() {
	dir, err := os.UserConfigDir()
	if err != nil {
		panic(err)
	}
	// 新版库名 dianbing；旧版 aiasset 兜底（未迁移过的库）
	path := filepath.Join(dir, "dianbing", "dianbing.db")
	if _, err := os.Stat(path); err != nil {
		if _, err2 := os.Stat(filepath.Join(dir, "aiasset", "aiasset.db")); err2 == nil {
			path = filepath.Join(dir, "aiasset", "aiasset.db")
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	fmt.Println("DB:", path)

	fmt.Println("== 按任务统计 ==")
	rows, err := db.Query(`SELECT task_id, COUNT(*), MIN(host), MAX(host), MIN(first_seen), MAX(last_seen)
		FROM assets GROUP BY task_id ORDER BY MAX(last_seen) DESC`)
	if err != nil {
		panic(err)
	}
	for rows.Next() {
		var task string
		var n int
		var minH, maxH, minT, maxT string
		rows.Scan(&task, &n, &minH, &maxH, &minT, &maxT)
		fmt.Printf("任务 %s | %d 条 | host范围 %s ~ %s | %s ~ %s\n", task, n, minH, maxH, minT, maxT)
	}
	rows.Close()

	fmt.Println("\n== 最近 20 条资产 ==")
	rows2, err := db.Query(`SELECT host, port, scheme, status, title, task_id, last_seen
		FROM assets ORDER BY last_seen DESC LIMIT 20`)
	if err != nil {
		panic(err)
	}
	for rows2.Next() {
		var h, sc, ti, task, ls string
		var p, st int
		rows2.Scan(&h, &p, &sc, &st, &ti, &task, &ls)
		fmt.Printf("%-18s:%d %-5s %d %-20s [%s] %s\n", h, p, sc, st, ti, task, ls)
	}
	rows2.Close()

	fmt.Println("\n== 任务审计 ==")
	rows3, err := db.Query(`SELECT task_id, mode, full_range, port_count, hosts_alive, ports_open,
		assets_found, started_at, finished_at FROM tasks ORDER BY started_at DESC LIMIT 20`)
	if err == nil {
		for rows3.Next() {
			var id, mode, st, fin string
			var fr, pc, ha, po, af int
			rows3.Scan(&id, &mode, &fr, &pc, &ha, &po, &af, &st, &fin)
			scope := fmt.Sprintf("%d 端口", pc)
			if fr == 1 {
				scope = "全端口 1-65535"
			}
			poStr := "不适用"
			if po >= 0 {
				poStr = fmt.Sprintf("%d", po)
			}
			fmt.Printf("%s | %s | %s | 存活 %d | 开放 %s | 资产 %d | %s ~ %s\n",
				id, mode, scope, ha, poStr, af, st, fin)
		}
		rows3.Close()
	} else {
		fmt.Println("(无任务审计表——旧版本任务未记录)")
	}

	fmt.Println("\n== 设置 ==")
	var raw string
	err = db.QueryRow(`SELECT value FROM settings WHERE key='main'`).Scan(&raw)
	if err == nil {
		fmt.Println(raw)
	} else {
		fmt.Println("(无设置记录)")
	}
}
