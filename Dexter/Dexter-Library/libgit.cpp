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
#include <git2.h>

#pragma comment (lib, "winhttp.lib")
#pragma comment (lib, "Rpcrt4.lib")

static std::string user;
static std::string pass;

//int match_cb(const char *path, const char *spec, void *payload)
//{
//	return 0;
//}

int get_credentials(git_cred** cred, const char* url, const char* username_from_url, unsigned int allowed_types, void* payload) {
	git_cred_userpass_plaintext_new(cred, user.c_str(), pass.c_str());
	return 0;
}

void print_git_error(int error) {
	const git_error *err = giterr_last();
	if (err) printf("ERROR %d: %s\n", err->klass, err->message);
	else printf("ERROR %d: no detailed info\n", error);
}

void libgit::init(void) {
	git_libgit2_init();
}

void libgit::finalize(void) {
	git_libgit2_shutdown();
}

bool libgit::commit(std::string username, std::string password, std::string email, std::string url, std::string folder, std::string PoC_KEYWORD, std::string data) {

	git_repository *repo = NULL;
	git_clone_options clone_options = GIT_CLONE_OPTIONS_INIT;
	git_checkout_options checkout_options = GIT_CHECKOUT_OPTIONS_INIT;
	char temp[MAX_PATH];
	GetTempPathA(MAX_PATH, temp);
	std::string temp_path = std::string(temp) + folder;
	bool success = true;
	user = username;
	pass = password;
	int error = 0;

	//git_index *index = NULL;
	//git_strarray paths = { nullptr, 0 };
	//paths.count = 1;
	//git_oid tree_oid, commit_oid;
	//const char *f = "*";
	//git_signature *signature = NULL;
	//git_tree *tree = NULL;
	//git_buf buffer;
	//git_remote* remote = NULL;
	//git_push_options options;

	checkout_options.checkout_strategy = GIT_CHECKOUT_SAFE;
	clone_options.checkout_opts = checkout_options;
	clone_options.fetch_opts.callbacks.credentials = get_credentials;

	if (success && (error = git_clone(&repo, url.c_str(), temp_path.c_str(), &clone_options)) != 0) {
		print_git_error(error);
		success = false;
	}

	/*if (success && (paths.strings = (char**)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(char*) * paths.count)) == NULL) {
		success = false;
	}

	if (success && (paths.strings[0] = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 4)) == NULL) {
		success = false;
	}

	if (success && strncpy_s(paths.strings[0], 4, f, _TRUNCATE) != 0) {
		success = false;
	}*/

	/*if (success && git_repository_init(&repo, temp_path.c_str(), FALSE) != 0) {
		success = false;
	}

	if (success && git_repository_index(&index, repo) != 0) {
		success = false;
	}*/

	/*if (success && git_index_add_all(index, &paths, GIT_INDEX_ADD_DEFAULT, NULL, NULL) != 0) {
		success = false;
	}*/

	/*if (success && git_index_write(index) != 0) {
		success = false;
	}

	if (success && git_index_write_tree(&tree_oid, index) != 0) {
		success = false;
	}

	if (success && git_signature_now(&signature, username.c_str(), email.c_str()) != 0) {
		success = false;
	}

	if (success && git_tree_lookup(&tree, repo, &tree_oid) != 0) {
		success = false;
	}

	SecureZeroMemory(&buffer, sizeof(git_buf));

	if (success && git_message_prettify(&buffer, "Initial commit", 0, '#') != 0) {
		success = false;
	}

	if (success && git_commit_create_v(&commit_oid, repo, "HEAD", signature, signature, NULL, buffer.ptr, tree, 0) != 0) {
		success = false;
	}*/

	/*if (success && git_remote_create(&remote, repo, "origin", host.c_str()) != 0) {
		success = false;
	}*/

	/*if (success && git_remote_lookup(&remote, repo, "origin") != 0) {
		success = false;
	}*/

	//pull/fetch??

	/*char *ref_str = new char[37];
	strncpy_s(ref_str, 37, "refs/heads/master:refs/heads/master", _TRUNCATE);
	const git_strarray refs = { &ref_str, 1 };
	git_push_init_options(&options, GIT_PUSH_OPTIONS_VERSION);
	git_remote_init_callbacks(&options.callbacks, GIT_REMOTE_CALLBACKS_VERSION);
	options.callbacks.credentials = get_credentials;
	git_remote_push(remote, &refs, &options);*/

	/*if (success && git_remote_connect(remote, GIT_DIRECTION_PUSH, &callbacks, NULL, NULL) != 0) {
		success = false;
	}

	if (success && git_remote_add_push(repo, git_remote_name(remote), "refs/heads/master:refs/heads/master") != 0) {
		success = false;
	}

	if (success && git_push_init_options(&options, GIT_PUSH_OPTIONS_VERSION) != 0) {
		success = false;
	}

	if (success && git_remote_upload(remote, NULL, &options) != 0) {
		success = false;
	}*/

	/*if (paths.strings[0]) {
		HeapFree(GetProcessHeap(), 0, paths.strings[0]);
		paths.strings[0] = NULL;
	}

	if (paths.strings) {
		HeapFree(GetProcessHeap(), 0, paths.strings);
		paths.strings = NULL;
	}*/

	/*git_buf_dispose(&buffer);

	if (signature) {
		git_signature_free(signature);
		signature = NULL;
	}

	if (tree) {
		git_tree_free(tree);
		tree = NULL;
	}

	if (remote) {
		git_remote_free(remote);
	}

	if (index) {
		git_index_free(index);
		index = NULL;
	}*/

	if (repo) {
		git_repository_free(repo);
		repo = NULL;
	}

	return success;
}
