package handlers

import (
	"backend/db"
	"backend/models"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func DownloadPosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	url := fmt.Sprint(r.URL)

	_, file := path.Split(url)

	imagePath := "./posts/" + file

	imagedata, err := ioutil.ReadFile(imagePath)
	if err != nil {
		http.Error(w, "Couldn't read the file", http.StatusInternalServerError)
		return
	}

	ext := strings.ToLower(filepath.Ext(file))

	contentType := models.GetExtension(ext)

	if contentType == "" {
		http.Error(w, "Unsupported file format", http.StatusUnsupportedMediaType)
		return
	}

	w.Header().Set("Content-Type", contentType)

	_, err = w.Write(imagedata)
	if err != nil {
		http.Error(w, "failed to write image data to response", http.StatusInternalServerError)
		return
	}
}

func PostMedia(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var postInfo models.InsertPost
	err := json.NewDecoder(r.Body).Decode(&postInfo)
	if err != nil {
		fmt.Fprintln(w, "Check input data field formats")
		return
	}

	//check for missing fields
	if postInfo.TurnOffComments == nil || postInfo.HideLikeCount == nil || postInfo.Location == nil || postInfo.UserID == nil || postInfo.PostCaption == nil {
		http.Error(w, "Missing field/fields in the request", http.StatusMethodNotAllowed)
		return
	}

	//validate input user id

	match, _ := regexp.MatchString("^.*[0-9]$", strconv.Itoa(int(*postInfo.UserID)))
	if !match {
		fmt.Fprintln(w, "check input post id format")
		return
	}

	if len(postInfo.HashtagIds) > 30 {
		http.Error(w, "You can use only 30 hashtags in the caption", http.StatusInternalServerError)
		return
	}
	if len(postInfo.TaggedIds) > 20 {
		http.Error(w, "Only 20 users can be tagged", http.StatusInternalServerError)
		return
	}

	var idexists bool
	err = db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE user_id=$1)", postInfo.UserID).Scan(&idexists)
	if err != nil {
		http.Error(w, "Invalid user-id", http.StatusInternalServerError)
		return
	}

	if !idexists {
		http.Error(w, "No user exists with this user-id", http.StatusInternalServerError)
		return
	}

	//check for existance of tagged ids

	for _, id := range postInfo.TaggedIds {
		err = db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE user_id=$1)", id).Scan(&idexists)
		if err != nil {
			http.Error(w, "Invalid user-id", http.StatusBadRequest)
			return
		}
		if !idexists {
			http.Error(w, "No user exists with this tagged id", http.StatusBadRequest)
			fmt.Fprint(w, id)
			return
		}
	}

	//check for existance of hash ids
	for _, id := range postInfo.HashtagIds {
		err = db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM hashtags WHERE hash_id=$1)", id).Scan(&idexists)
		if err != nil {
			http.Error(w, "Invalid hash-id", http.StatusInternalServerError)
			return
		}
		if !idexists {
			http.Error(w, "Invalid hash-id", http.StatusInternalServerError)
			return
		}
	}

	// //validate input location format
	if *postInfo.Location != "" {
		pointRegex := regexp.MustCompile(`^[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)$`)
		if !pointRegex.MatchString(*postInfo.Location) {
			fmt.Fprintln(w, "check input location format")
			return
		}
	} else {
		*postInfo.Location = "0,0" //stuff user location when there is access
	}

	//check for max length of post caption 150 chars
	if len(*postInfo.PostCaption) > 2200 {
		http.Error(w, "Max allowed length of post caption is 2200 character", http.StatusNotAcceptable)
		return
	}

	var postId models.PostId
	insertPostInfo := `INSERT INTO posts(user_id,poat_caption,location,hide_like,hide_comments) VALUES($1,$2,$3,$4,$5) RETURNING post_id`
	err = db.DB.QueryRow(insertPostInfo, postInfo.UserID, postInfo.PostCaption, postInfo.Location, postInfo.HideLikeCount, postInfo.TurnOffComments).Scan(&postId.PostId)
	if err != nil {
		panic(err)
	}

	//update tags
	for _, tagid := range postInfo.TaggedIds {
		_, err = db.DB.Query("INSERT INTO tagged_users(post_id,tagged_ids) VALUES($1,$2)", postId.PostId, tagid)
		if err != nil {
			db.DB.Query("DELETE FROM posts WHERE post_id=$1", postId.PostId)
			http.Error(w, "Error inserting tagged users", http.StatusInternalServerError)
			return
		}

	}

	//check for hashtags

	for _, hashid := range postInfo.HashtagIds {
		_, err = db.DB.Query("INSERT INTO mentions(hash_id,post_id) VALUES($1,$2)", hashid, postId.PostId)
		if err != nil {
			fmt.Println(err)
			db.DB.Query("DELETE FROM tagged_users WHERE post_id=$1", postId.PostId)
			http.Error(w, "Error inserting mentions", http.StatusInternalServerError)
			return
		}
	}

	json.NewEncoder(w).Encode(postId)

	fmt.Fprintf(w, "Posts uploaded successfully.")

}

func PostMediaPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096*MB)
	err := r.ParseMultipartForm(4096 * MB)
	if err != nil {
		http.Error(w, "Error parsing multipart form data", http.StatusInternalServerError)
		return
	}
	jsonData := r.FormValue("postId")

	var postId models.PostId

	err = json.Unmarshal([]byte(jsonData), &postId)
	if err != nil {

		http.Error(w, "Error unmarshalling JSON data,Enter correct postID", http.StatusInternalServerError)
		return
	}

	var tempid int64
	err = db.DB.QueryRow("SELECT post_id FROM posts WHERE post_id=$1", postId.PostId).Scan(&tempid)
	if err != nil {
		http.Error(w, "Invalid post_id", http.StatusInternalServerError)
		return
	}

	if tempid != postId.PostId {
		http.Error(w, "Invalid post_id", http.StatusInternalServerError)
		return
	}

	var postPath []string
	fileHeaders := r.MultipartForm.File
	if len(fileHeaders) == 0 {
		http.Error(w, "No files attached", http.StatusInternalServerError)
		return
	}

	for _, fileHeaders := range fileHeaders {
		for _, fileHeader := range fileHeaders {
			if len(fileHeaders) > 10 {
				http.Error(w, "Only 10 files allowed", http.StatusInternalServerError)
				return
			}
			file, err := fileHeader.Open()
			if err != nil {
				http.Error(w, "Unable to open the file", http.StatusInternalServerError)
				return
			}
			defer file.Close()

			//check for file allowed file format
			match, _ := regexp.MatchString("^.*\\.(jpg|JPG|png|PNG|JPEG|jpeg|bmp|BMP|MP4|mp4|mov|MOV|GIF|gif)$", fileHeader.Filename)
			if !match {
				fmt.Fprintln(w, "Only JPG,JPEG,PNG,BMP formats are allowed for upload")
				return
			} else {
				//check for the file size
				if size := fileHeader.Size; size > 8*MB {
					http.Error(w, "File size exceeds 8MB", http.StatusInternalServerError)
					return
				}
			}

			// image, _, err := image.DecodeConfig(file)
			// if err != nil {
			// 	http.Error(w, "Cannot read the image configs", http.StatusInternalServerError)
			// 	return
			// }

			// if image.Height < 155 && image.Width < 155 {
			// 	http.Error(w, "Image resolution too low", http.StatusInternalServerError)
			// 	return
			// }

			// fmt.Fprintln(w, fileHeader.Filename, ":", image.Width, "x", image.Height)

			if match, _ := regexp.MatchString("^.*\\.(MP4|mp4|mov|MOV|GIF|gif)$", fileHeader.Filename); match {
				//check for the file size
				if size := fileHeader.Size; size > 3584*MB {
					http.Error(w, "File size exceeds 3.6GB", http.StatusInternalServerError)
					return
				}

			}

			//Create a new file on the server
			//get cleaned file name
			s := regexp.MustCompile(`\s+`).ReplaceAllString(fileHeader.Filename, "")
			time := fmt.Sprintf("%v", time.Now())
			s = regexp.MustCompile(`\s+`).ReplaceAllString(time, "") + s

			dst, err := os.Create(filepath.Join("./posts", s))
			if err != nil {
				http.Error(w, "Unable to create a file", http.StatusInternalServerError)
				return
			}
			defer dst.Close()

			_, err = io.Copy(dst, file)
			if err != nil {
				http.Error(w, "Unable to write file", http.StatusInternalServerError)
				return
			}

			postPath = append(postPath, filepath.Join("./posts", s))

		}

	}
	requestBodyPostPath := fmt.Sprintf("%s", strings.Join(postPath, ","))
	insertPostPath := `UPDATE posts SET post_path=$1,complete_post=$2 WHERE post_id=$3`
	_, err = db.DB.Query(insertPostPath, requestBodyPostPath, true, postId.PostId)
	if err != nil {
		panic(err)
		// http.Error(w, "Error inserting to DB", http.StatusInternalServerError)

	}

	json.NewEncoder(w).Encode("Media uploaded successfully")
}

func AllPosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var userPosts []models.UsersPost

	var userId models.UserID
	// userId.UserId = 1
	err := json.NewDecoder(r.Body).Decode(&userId)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusMethodNotAllowed)
		return
	}
	if userId.UserId == 0 {
		fmt.Fprintln(w, "Invalid user id or missing field")
		return
	}

	getPosts := `SELECT post_id,post_path,poat_caption,location,hide_like,hide_comments,posted_on FROM posts WHERE user_id=$1 ORDER BY posted_on DESC`
	row, err := db.DB.Query(getPosts, userId.UserId)
	if err != nil {
		panic(err)
	}
	for row.Next() {
		//to get username
		var userPost models.UsersPost
		getUserName := `SELECT user_name,display_pic FROM users WHERE user_id=$1`
		var url string
		err = db.DB.QueryRow(getUserName, userId.UserId).Scan(&userPost.UserName, &url)

		userPost.UserProfilePicURL = "http://localhost:3000/getProfilePic/" + url
		if err != nil {
			http.Error(w, "Unable to get username", http.StatusInternalServerError)
			return
		}
		var postURLstr string
		err = row.Scan(&userPost.PostId, &postURLstr, &userPost.PostCaption, &userPost.AttachedLocation, &userPost.HideLikeCount, &userPost.HideLikeCount, &userPost.PostedOn)
		if err != nil {
			panic(err)
		}

		//get like status of present user
		err = db.DB.QueryRow("SELECT EXISTS(SELECT user_name FROM likes WHERE post_id=$1 AND user_name=$2)", userPost.PostId, userPost.UserName).Scan(&userPost.LikeStatus)
		if err != nil {
			panic(err)
		}

		//get count of likes
		err = db.DB.QueryRow("SELECT COUNT(user_name) FROM likes WHERE post_id=$1", userPost.PostId).Scan(&userPost.Likes)
		if err != nil {
			panic(err)
		}
		postURL := strings.Split(postURLstr, ",")
		for _, url := range postURL {
			url = "http://localhost:3000/download/" + url
			userPost.PostURL = append(userPost.PostURL, url)

		}

		err = db.DB.QueryRow("SELECT user_id,post_id FROM savedposts WHERE user_id=$1.post_id=$2", userPost.UserID, userPost.PostId).Scan(&userPost.UserID, &userPost.PostId)
		if err != nil {
			userPost.SavedStatus = false
		} else {
			userPost.SavedStatus = true
		}

		userPost.UserID = userId.UserId
		userPosts = append(userPosts, userPost)
	}
	json.NewEncoder(w).Encode(userPosts)

}
