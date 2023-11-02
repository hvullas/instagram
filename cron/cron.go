package cron

import (
	"backend/db"
	"log"

	"github.com/robfig/cron/v3"
)

func Run() {
	//cron delete stories after 24 hours

	//cron delete posts which are not updated with media
	cron := cron.New()

	cron.AddFunc("29 16 * * *", func() {

		//_,err=db.Query("DELETE FROM posts WHERE complete_post=$1",false)
		_, err := db.DB.Query("DELETE FROM example WHERE timestamp<= current_timestamp - interval '10 minute'")
		if err != nil {
			log.Panic(err)
			return
		}
		log.Println("cron active")
	})
	cron.Start()
}
