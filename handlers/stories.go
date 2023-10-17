package handlers

import (
	"backend/db"
	"backend/models"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func UploadStory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var storyinfo models.StoryInfo
	err := json.NewDecoder(r.Body).Decode(&storyinfo)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	if len(storyinfo.TaggedIds) > 20 {
		http.Error(w, "Maximum 20 ids allowed", http.StatusBadRequest)
		return
	}
	var idexists bool
	err = db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE user_id=$1)", storyinfo.UserID).Scan(&idexists)
	if err != nil {
		http.Error(w, "Invalid user-id", http.StatusBadRequest)
		return
	}
	if !idexists {
		http.Error(w, "Invalid user-id", http.StatusBadRequest)
		return
	}

	var storyIds []models.ReturnedStoryId

	//check for existance of all tagged ids
	for _, ids := range storyinfo.TaggedIds {

		var returnedStoryId models.ReturnedStoryId
		err = db.DB.QueryRow("INSERT INTO stories(user_id,story_path) VALUES($1,$2) RETURNING story_id", storyinfo.UserID, "").Scan(&returnedStoryId.ReturnedStoryId)
		if err != nil {
			panic(err)
		}

		returnedStoryId.PostAsStory = false
		storyIds = append(storyIds, returnedStoryId)

		for _, id := range ids {
			var count int64
			err = db.DB.QueryRow("SELECT COUNT(story_id) FROM stories WHERE user_id=$1", storyinfo.UserID).Scan(&count)
			if err != nil {
				http.Error(w, "Error retrieving count of stories of a user", http.StatusInternalServerError)
				return
			}

			if count < 100 {

				err = db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE user_id=$1)", id).Scan(&idexists)
				if err != nil {
					http.Error(w, "Invalid user-id", http.StatusInternalServerError)
					return
				}
				if !idexists {
					http.Error(w, "No user exists with this id:", http.StatusInternalServerError)
					fmt.Fprint(w, id)
					return
				}
				_, err = db.DB.Query("INSERT INTO story_tags(story_id,tagged_id) VALUES($1,$2)", returnedStoryId.ReturnedStoryId, id)
				if err != nil {
					log.Panic(err)
					// http.Error(w, "Error inserting to story_tags table", http.StatusInternalServerError)
					// return
				}
			} else {
				_, err = db.DB.Query("DELETE FROM stories WHERE story_id=(SELECT MIN(story_id) WHERE user_id=$1)", storyinfo.UserID)
				if err != nil {
					http.Error(w, "Coudn't delete initial post ", http.StatusInternalServerError)
					return
				}
				err = db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE user_id=$1)", id).Scan(&idexists)
				if err != nil {
					http.Error(w, "Invalid user-id", http.StatusInternalServerError)
					return
				}
				if !idexists {
					http.Error(w, "No user exists with this id:", http.StatusInternalServerError)
					fmt.Fprint(w, id)
					return
				}
				_, err = db.DB.Query("INSERT INTO story_tags(story_id,tagged_id) VALUES($1,$2)", returnedStoryId, id)
				if err != nil {
					http.Error(w, "Error inserting to story_tags table", http.StatusInternalServerError)
					return
				}
			}

		}
	}
	json.NewEncoder(w).Encode(storyIds)

}

func UploadStoryPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1024*MB)
	err := r.ParseMultipartForm(1024 * MB)
	if err != nil {
		http.Error(w, "Error parsing multipart form data or file size may be out of bound", http.StatusInternalServerError)
		return
	}

	jsonData := r.FormValue("storyId")

	var storyinfo models.StoryMedia

	err = json.Unmarshal([]byte(jsonData), &storyinfo)
	if err != nil {
		http.Error(w, "Error unmarshalling JSON data", http.StatusBadRequest)
		return
	}

	//validate storyId
	var storyExists bool
	err = db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM stories WHERE story_id=$1)", storyinfo.StoryId).Scan(&storyExists)
	if err != nil {
		http.Error(w, "Invalid storyId", http.StatusBadRequest)
		return
	}

	file, fileHeader, err := r.FormFile("media")
	if err != nil {
		http.Error(w, "Missing formfile", http.StatusNoContent)
		return
	}

	//get cleaned file name
	s := regexp.MustCompile(`\s+`).ReplaceAllString(fileHeader.Filename, "")
	time := fmt.Sprintf("%v", time.Now())
	s = regexp.MustCompile(`\s+`).ReplaceAllString(time, "") + s

	file, err = fileHeader.Open()
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
		if size := fileHeader.Size; size > 30*MB {
			http.Error(w, "File size exceeds 30MB", http.StatusInternalServerError)
			return
		}
	}

	if match, _ := regexp.MatchString("^.*\\.(MP4|mp4|mov|MOV|GIF|gif)$", fileHeader.Filename); match {
		//check for the file size
		if size := fileHeader.Size; size > 1024*MB {
			http.Error(w, "File size exceeds 1GB", http.StatusInternalServerError)
			return
		}

	}

	dst, err := os.Create(filepath.Join("./stories", s))
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
	storyPath := "stories/" + s

	var upload models.UploadStory
	err = db.DB.QueryRow("UPDATE stories SET story_path=$1,success=$2 WHERE story_id=$3 RETURNING story_id,success", storyPath, true, storyinfo.StoryId).Scan(&upload.StoryId, &upload.Uploaded)
	if err != nil {
		http.Error(w, "Invalid id", http.StatusBadRequest)
		delete := "./" + storyPath
		os.Remove(delete)

		// http.Error(w, "Error inserting story media", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(upload)

}

func GetStory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var storyid models.StoryMedia
	err := json.NewDecoder(r.Body).Decode(&storyid)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	if storyid.StoryId <= 0 {
		http.Error(w, "Invalid id or missing field", http.StatusBadRequest)
		return
	}

	//validate storyId
	var storyExists bool
	err = db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM stories WHERE story_id=$1)", storyid.StoryId).Scan(&storyExists)
	if err != nil {
		http.Error(w, "Invalid storyId", http.StatusBadRequest)
		return
	}

	if !storyExists {
		http.Error(w, "Invalid storyId", http.StatusBadRequest)
		return
	}

	var getstory models.GetStory
	err = db.DB.QueryRow("SELECT story_id,story_path,posted_on,success FROM stories WHERE story_id=$1", storyid.StoryId).Scan(&getstory.StoryId, &getstory.StoryURL, &getstory.PostedOn, &getstory.Success)
	if err != nil {
		panic(err)
	}

	row, err := db.DB.Query("SELECT tagged_id FROM story_tags WHERE story_id=$1", storyid.StoryId)
	if err != nil {
		http.Error(w, "Error getting tagged ids", http.StatusInternalServerError)
		return
	}

	for row.Next() {
		var tagged_ids int64
		err = row.Scan(&tagged_ids)
		if err != nil {
			http.Error(w, "Scan error on tagged_id", http.StatusInternalServerError)
			return
		}

		getstory.TaggedIds = append(getstory.TaggedIds, tagged_ids)

	}
	filetype := strings.Split(getstory.StoryURL, ".")
	getstory.FileType = models.GetExtension("." + filetype[len(filetype)-1])
	getstory.StoryURL = "http://localhost:3000/download/" + getstory.StoryURL

	json.NewEncoder(w).Encode(getstory)

}

func DownloadStory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	url := fmt.Sprint(r.URL)

	_, file := path.Split(url)

	imagePath := "./stories/" + file

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

func DeleteStory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var storyid models.StoryMedia
	err := json.NewDecoder(r.Body).Decode(&storyid)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	if storyid.StoryId <= 0 {
		http.Error(w, "Invalid id or missing field", http.StatusBadRequest)
		return
	}

	var storypath string
	err = db.DB.QueryRow("SELECT story_path FROM stories WHERE story_id=$1", storyid.StoryId).Scan(&storypath)
	if err != nil {
		http.Error(w, "Invalid id", http.StatusBadRequest)
		return
	}

	filelocation := "./" + storypath

	os.Remove(filelocation)

	_, err = db.DB.Query("DELETE FROM stories WHERE story_id=$1", storyid.StoryId)
	if err != nil {
		http.Error(w, "Error deleting story", http.StatusInternalServerError)
		return
	}
	fmt.Fprintln(w, "Deleted successfully")

}

func StoryUploadStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not allowed", http.StatusMethodNotAllowed)
		return
	}
	var story_id models.PostId
	err := json.NewDecoder(r.Body).Decode(&story_id)
	if err != nil {
		panic(err)
	}
	var postUploadStatus models.SavedStatus
	err = db.DB.QueryRow("SELECT success FROM stories WHERE story_id=$1", story_id.PostId).Scan(&postUploadStatus.SavedStatus)
	if err != nil {
		http.Error(w, "Invalid story id", http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(postUploadStatus)
}

func AllActiveStories(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not allowed", http.StatusMethodNotAllowed)
		return
	}
	var userId UserID
	err := json.NewDecoder(r.Body).Decode(&userId)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusMethodNotAllowed)
		return
	}

	var following []int64
	row, err := db.Query("SELECT follower_id FROM follower WHERE user_id=$1 AND accepted=$2", userId.UserId, true)
	if err != nil {
		log.Panicln("no follwings", err)
	}
	for row.Next() {
		var id int64
		err = row.Scan(&id)
		if err == sql.ErrNoRows {
			fmt.Fprintln(w, "null")
			return
		}
		following = append(following, id)
	}

	var activeStory []ActiveStories
	for _, id := range following {
		var story ActiveStories
		row, err := db.Query("SELECT story_id FROM stories WHERE user_id=$1 AND success =$2", id, true)
		if err != nil {
			panic(err)
		}
		err = db.QueryRow("SELECT user_name,display_pic FROM users WHERE user_id=$1", id).Scan(&story.User_name, &story.Profile_picURL)
		if err != nil {
			log.Panicln(err)
		}
		story.Profile_picURL = "http://localhost:3000/getProfilePic/profilePhoto/" + story.Profile_picURL

		story.User_id = id
		for row.Next() {
			var story_id int64
			err = row.Scan(&story_id)
			if err != nil {
				log.Panicln("no story id")
			}
			story.Story_id = append(story.Story_id, story_id)
			err = db.QueryRow("SELECT seen_status FROM story_seen_status WHERE user_id=$1 AND story_id=$2", userId.UserId, story_id).Scan(&story.Seen_status)
			if err != nil {
				//log.Panicln("no seen status", err)
				continue
			}

		}
		activeStory = append(activeStory, story)
	}
	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(activeStory)
}
