package handlers

import (
	"backend/db"
	"backend/models"
	"encoding/json"
	"fmt"
	"net/http"
)

func CommentPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var requestBody models.CommentBody
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusNotAcceptable)
		return
	}
	//validate for proper userId and PostId
	if requestBody.PostId == 0 || requestBody.UserID == 0 {
		fmt.Fprintln(w, "Invalid userId or PostId or missing fields")
		return
	}
	if requestBody.CommentBody == "" {
		http.Error(w, "CommentBody cannot be empty or missing field", http.StatusNotAcceptable)
		return
	}

	if len(requestBody.CommentBody) > 2500 {
		http.Error(w, "Comment body should not exceed 2500 characters", http.StatusNotAcceptable)
		return
	}

	insertComment := `INSERT INTO comments(commentoruser_id,post_id,comment_body) VALUES($1,$2,$3) RETURNING comment_id`
	var returnedCommentId models.ReturnedCommentId

	err = db.DB.QueryRow(insertComment, requestBody.UserID, requestBody.PostId, requestBody.CommentBody).Scan(&returnedCommentId.ReturnedCommentId)
	if err != nil {
		http.Error(w, "Invalid post id", http.StatusBadRequest)
	}
	json.NewEncoder(w).Encode(returnedCommentId)

}
func AllComments(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var postId models.PostId
	err := json.NewDecoder(r.Body).Decode(&postId)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusMethodNotAllowed)
		return
	}
	if postId.PostId == 0 {
		fmt.Fprintln(w, "Invalid post id")
		return
	}

	err = db.DB.QueryRow("SELECT post_id FROM posts WHERE post_id=$1", postId.PostId).Scan(&postId.PostId)
	if err != nil {
		http.Error(w, "Invalid post id", http.StatusInternalServerError)
		return
	}

	var comments []models.CommentsOfPost
	var comment models.CommentsOfPost
	row, err := db.DB.Query("SELECT commentoruser_id,comment_id,comment_body,commented_on FROM comments WHERE post_id=$1 ORDER BY commented_on DESC", postId.PostId)
	if err != nil {
		panic(err)
	}
	for row.Next() {
		var commentorUSerID int64
		err = row.Scan(&commentorUSerID, &comment.CommentId, &comment.CommentBody, &comment.CommentedOn)
		if err != nil {
			panic(err)
		}

		var dpURL string
		err = db.DB.QueryRow("SELECT user_name,display_pic FROM users WHERE user_id=$1", commentorUSerID).Scan(&comment.CommentorUserName, &dpURL)
		if err != nil {
			panic(err)
		}
		comment.CommentorDisplayPic = "http://localhost:3000/getProfilePic/" + dpURL
		comment.PostId = postId.PostId
		comments = append(comments, comment)

	}
	json.NewEncoder(w).Encode(comments)

}
func TurnOffComments(w http.ResponseWriter, r *http.Request) {
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

	_, err = db.DB.Query("UPDATE posts SET hide_comments=$1 WHERE user_id=$2", true, commentoff.UserID)
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(w, "Comments turned off")

}
func TurnONComments(w http.ResponseWriter, r *http.Request) {
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

	_, err = db.DB.Query("UPDATE posts SET hide_comments=$1 WHERE user_id=$2", false, commentoff.UserID)
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(w, "Comments turned on")

}
func DeleteComment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var deleteComment models.DeleteComment
	err := json.NewDecoder(r.Body).Decode(&deleteComment)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	if deleteComment.CommentId <= 0 || deleteComment.PostId <= 0 || deleteComment.UserID <= 0 {
		http.Error(w, "Missing fields or inavlid ids", http.StatusResetContent)
		return
	}

	err = db.DB.QueryRow("SELECT user_id,post_id FROM posts WHERE user_id=$1 AND post_id=$2", deleteComment.UserID, deleteComment.PostId).Scan(&deleteComment.UserID, &deleteComment.PostId)
	if err != nil {
		http.Error(w, "Invalid Ids for operation", http.StatusInternalServerError)
		return
	}

	err = db.DB.QueryRow("SELECT post_id,comment_id FROM comments WHERE post_id=$1 AND comment_id=$2", deleteComment.PostId, deleteComment.CommentId).Scan(&deleteComment.PostId, &deleteComment.CommentId)
	if err != nil {
		http.Error(w, "Invalid Ids for operation", http.StatusInternalServerError)
		return
	}

	_, err = db.DB.Query("DELETE FROM comments WHERE post_id=$1 AND comment_id=$2", deleteComment.PostId, deleteComment.CommentId)
	if err != nil {
		http.Error(w, "error deleting comment", http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "Comment deleted succefully")

}
