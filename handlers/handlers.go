package handlers

import (
	"backend/db"
	"backend/models"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
)

const MB = 1 << 20

func GetPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	//:var id int64
	idstr := fmt.Sprint(r.URL)

	_, idstr = path.Split(idstr)

	postId, err := strconv.Atoi(idstr)
	if err != nil {
		http.Error(w, "Bad post id", http.StatusMethodNotAllowed)
		return
	}

	err = db.DB.QueryRow("SELECT post_id FROM posts WHERE post_id=$1 AND complete_post=$2", postId, true).Scan(&postId)
	if err != nil {
		http.Error(w, "Invalid postId or does not exist", http.StatusInternalServerError)
		return
	}
	var post models.UsersPost

	post.PostId = int64(postId)

	var postURL string
	query := `SELECT user_id,post_path,poat_caption,location,hide_like,hide_comments,posted_on FROM posts WHERE post_id=$1 AND complete_post=$2`
	err = db.DB.QueryRow(query, postId, true).Scan(&post.UserID, &postURL, &post.PostCaption, &post.AttachedLocation, &post.HideLikeCount, &post.TurnOffComments, &post.PostedOn)
	if err != nil {
		// http.Error(w, "Error fetching data from db posts", http.StatusInternalServerError)
		// return
		panic(err)
	}

	filetype := strings.Split(postURL, ".")
	post.FileType = models.GetExtension("." + filetype[len(filetype)-1])

	postURL = "http://localhost:3000/download/" + postURL
	post.PostURL = append(post.PostURL, postURL)

	var URL string
	err = db.DB.QueryRow("SELECT user_name,display_pic FROM users WHERE user_id=$1", post.UserID).Scan(&post.UserName, &URL)
	if err != nil {
		http.Error(w, "Error retriving data from db users", http.StatusInternalServerError)
		return
	}
	post.UserProfilePicURL = "http://localhost:3000/getProfilePic/" + URL

	err = db.DB.QueryRow("SELECT COUNT(user_name) FROM likes WHERE post_id=$1", postId).Scan(&post.Likes)
	if err != nil {
		http.Error(w, "Error retriving likes count", http.StatusInternalServerError)
		return
	}

	//pending : update like status

	err = json.NewEncoder(w).Encode(post)
	if err != nil {
		// http.Error(w,"Error encoding response",http.StatusInternalServerError)
		fmt.Fprintln(w, "Error encoding response")
		return
	}

}

func SearchAccounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var username models.UserName
	err := json.NewDecoder(r.Body).Decode(&username)
	if err != nil {
		http.Error(w, "error decoding request body", http.StatusBadRequest)
		return
	}

	if username.UserName == "" {
		http.Error(w, "Invalid user name or missing field", http.StatusPartialContent)
		return
	}

	str := regexp.MustCompile(`[a-zA-Z]*`)
	name := str.FindAllString(username.UserName, 1)

	num := regexp.MustCompile(`\d+`)
	number := num.FindAllString(username.UserName, 1)

	var like string
	if len(number) == 0 {
		like = "%" + name[0] + "%"
	}
	if len(name) == 0 {
		like = "%" + number[0] + "%"
	}
	if len(name) != 0 && len(number) != 0 {
		like = "%" + name[0] + "%" + number[0] + "%"
	}
	row, err := db.DB.Query("SELECT user_id,user_name,name,display_pic FROM users WHERE user_name ILIKE $1", like)
	if err != nil {
		panic(err)
	}

	var accounts []models.Accounts
	for row.Next() {
		var acc models.Accounts
		err = row.Scan(&acc.UserID, &acc.UserName, &acc.Name, &acc.ProfilePic)
		if err != nil {
			panic(err)
		}
		acc.ProfilePic = "http://localhost:3000/getProfilePic/" + acc.ProfilePic
		accounts = append(accounts, acc)

	}

	json.NewEncoder(w).Encode(accounts)
}

func SearchHashtag(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var hashtag models.HashtagSearch
	err := json.NewDecoder(r.Body).Decode(&hashtag)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusPartialContent)
		return
	}
	str := regexp.MustCompile(`[a-zA-Z_]*`)
	name := str.FindAllString(hashtag.Hashtag, 1)

	num := regexp.MustCompile(`\d+`)
	number := num.FindAllString(hashtag.Hashtag, 1)

	var like string
	if len(number) == 0 {
		like = name[0] + "%"
	}
	if len(name) == 0 {
		like = number[0] + "%"
	}
	if len(name) != 0 && len(number) != 0 {
		like = name[0] + "%" + number[0] + "%"
	}

	row, err := db.DB.Query("SELECT hash_id,hash_name FROM hashtags WHERE hash_name ILIKE $1", like)
	if err != nil {
		panic(err)
	}

	var results []models.HashtagSearchResult
	for row.Next() {
		var result models.HashtagSearchResult
		err = row.Scan(&result.HashId, &result.HashName)
		if err != nil {
			http.Error(w, "error reading hashtable", http.StatusInternalServerError)
			return
		}

		if result.HashId == 0 {
			fmt.Println("its empty")

		}

		err = db.DB.QueryRow("SELECT COUNT(post_id) FROM mentions WHERE hash_id=$1", result.HashId).Scan(&result.PostCount)
		if err != nil {
			http.Error(w, "Error getting count of posts of hash", http.StatusInternalServerError)
			return
		}

		results = append(results, result)

	}
	var newhashtag models.Newhashtag
	if len(results) == 0 {

		err = db.DB.QueryRow("INSERT INTO hashtags(hash_name) VALUES($1) RETURNING hash_id", hashtag.Hashtag).Scan(&newhashtag.NewHashId)
		if err != nil {
			panic(err)
			// http.Error(w, "Error creating new hash", http.StatusInternalServerError)
			// return
		}

		json.NewEncoder(w).Encode(newhashtag)

	}

	if len(results) != 0 {
		json.NewEncoder(w).Encode(results)
	}

}

func PostUploadStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not allowed", http.StatusMethodNotAllowed)
		return
	}
	var post_id models.PostId
	err := json.NewDecoder(r.Body).Decode(&post_id)
	if err != nil {
		panic(err)
	}
	var postUploadStatus models.SavedStatus
	err = db.DB.QueryRow("SELECT complete_post FROM posts WHERE post_id=$1", post_id.PostId).Scan(&postUploadStatus.SavedStatus)
	if err != nil {
		panic(err)
	}

	json.NewEncoder(w).Encode(postUploadStatus)
}
