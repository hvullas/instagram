package handlers

import (
	"backend/db"
	"backend/models"
	"encoding/json"
	"fmt"
	"net/http"
)

func LikePosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var requestBody models.LikePost
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusMethodNotAllowed)
		return
	}
	//validate for proper userId and PostId
	if requestBody.PostId == 0 || requestBody.UserID == 0 {
		fmt.Fprintln(w, "Invalid userId or PostId/missing fields")
		return
	}

	getUserName := `SELECT user_name FROM users WHERE user_id=$1`
	var userName string
	err = db.DB.QueryRow(getUserName, requestBody.UserID).Scan(&userName)
	if err != nil {
		panic(err)
	}

	insertLike := `INSERT INTO likes(post_id,user_name) VALUES($1,$2)`
	_, err = db.DB.Query(insertLike, requestBody.PostId, userName)
	if err != nil {

		_, err := db.DB.Query("DELETE FROM likes WHERE user_name=$1", userName)
		if err != nil {
			panic(err)
		}

	}

	getTotalLikes := `SELECT COUNT(user_name) FROM likes WHERE post_id=$1`
	var likes models.TotalLikes
	err = db.DB.QueryRow(getTotalLikes, requestBody.PostId).Scan(&likes.TotalLikes)
	if err != nil {
		panic(err)
	}
	json.NewEncoder(w).Encode(likes)
}

func HideLikeCount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var commentoff models.LikePost //reusing struct fields
	err := json.NewDecoder(r.Body).Decode(&commentoff)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	if commentoff.PostId <= 0 || commentoff.UserID <= 0 {
		fmt.Fprintln(w, "Invalid ids or missing field")
		return
	}

	err = db.DB.QueryRow("SELECT user_id,post_id FROM posts WHERE user_id=$1 AND post_id=$2", commentoff.UserID, commentoff.PostId).Scan(&commentoff.UserID, &commentoff.PostId)
	if err != nil {
		panic(err)
	}

	_, err = db.DB.Query("UPDATE posts SET hide_like=$1 WHERE user_id=$2", true, commentoff.UserID)
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(w, "updated hide_like=true")

}

func ShowLikeCount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var commentoff models.LikePost //reusing struct fields
	err := json.NewDecoder(r.Body).Decode(&commentoff)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	if commentoff.PostId <= 0 || commentoff.UserID <= 0 {
		fmt.Fprintln(w, "Invalid ids or missing field")
		return
	}

	err = db.DB.QueryRow("SELECT user_id,post_id FROM posts WHERE user_id=$1 AND post_id=$2", commentoff.UserID, commentoff.PostId).Scan(&commentoff.UserID, &commentoff.PostId)
	if err != nil {
		panic(err)
	}

	_, err = db.DB.Query("UPDATE posts SET hide_like=$1 WHERE user_id=$2", false, commentoff.UserID)
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(w, "updated hide_likes=false")

}
