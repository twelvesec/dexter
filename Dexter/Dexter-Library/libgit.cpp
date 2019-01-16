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
#include <vector>

#pragma comment (lib, "winhttp.lib")
#pragma comment (lib, "Rpcrt4.lib")

char *user;
char *pass;

//int match_cb(const char *path, const char *spec, void *payload)
//{
//	return 0;
//}

//unsigned long long
//last_write_time(const std::string& path)
//{
//	wchar_t* wpath = new wchar_t[path.length() + 1]();
//
//	MultiByteToWideChar(CP_OEMCP, MB_PRECOMPOSED,
//		path.c_str(), path.length(),
//		wpath, path.length());
//
//	HANDLE file_handle = CreateFile(wpath,
//		GENERIC_READ,
//		FILE_SHARE_READ,
//		NULL,
//		OPEN_EXISTING,
//		FILE_ATTRIBUTE_NORMAL,
//		NULL);
//
//	delete[] wpath;
//	if (GetLastError() == ERROR_FILE_NOT_FOUND)
//	{
//		CloseHandle(file_handle);
//		return 0ull - 1ull;
//	}
//
//	FILETIME last_write_time;
//	if (!GetFileTime(file_handle, NULL, NULL, &last_write_time))
//	{
//		CloseHandle(file_handle);
//		return 0ull - 1ull;
//	}
//	CloseHandle(file_handle);
//
//	ULARGE_INTEGER result;
//	result.HighPart = last_write_time.dwHighDateTime;
//	result.LowPart = last_write_time.dwLowDateTime;
//
//	return result.QuadPart;
//}
//
//void
//index_entry_free(git_index_entry* entry)
//{
//	delete[] entry->path;
//	delete entry;
//}
//
//void
//index_entry_copy(git_index_entry* destination, const git_index_entry* source)
//{
//	*destination = *source;
//
//	size_t path_length = strlen(source->path) + 1;
//	char* buffer = new char[path_length];
//	memcpy_s(buffer, path_length, source->path, path_length);
//	destination->path = buffer;
//}
//
//void
//merge_conflict_resolve(git_index* index, std::string& ours_root, std::string& theirs_root)
//{
//	git_index_conflict_iterator*	conflict_ite;
//	git_index_conflict_iterator_new(&conflict_ite, index);
//
//	std::vector<git_index_entry*> unconflicted_entries;
//
//	const git_index_entry *ancestor, *ours, *theirs;
//	while (git_index_conflict_next(&ancestor, &ours, &theirs,
//		conflict_ite) != GIT_ITEROVER)
//	{
//		unsigned long long ours_time, theirs_time;
//		ours_time = last_write_time(ours_root + ours->path);
//		theirs_time = last_write_time(theirs_root + theirs->path);
//
//		git_index_entry* resolution = new git_index_entry;
//		if (ours_time > theirs_time)
//			index_entry_copy(resolution, ours);
//		else
//			index_entry_copy(resolution, theirs);
//
//		GIT_IDXENTRY_STAGE_SET(resolution, GIT_INDEX_STAGE_NORMAL);
//		if (!(resolution->flags & GIT_IDXENTRY_VALID))
//			resolution->flags |= GIT_IDXENTRY_VALID;
//
//		unconflicted_entries.push_back(resolution);
//	}
//
//
//	for (auto ite = unconflicted_entries.begin();
//		ite != unconflicted_entries.end(); ite++)
//	{
//		git_index_add(index, (*ite));
//
//		git_index_conflict_remove(index, (*ite)->path);
//
//		index_entry_free(*ite);
//	}
//
//	git_index_conflict_iterator_free(conflict_ite);
//}

int get_credentials(git_cred** cred, const char* url, const char* username_from_url, unsigned int allowed_types, void* payload) {
	git_cred_userpass_plaintext_new(cred, user, pass);
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
	git_remote* remote = NULL;

	git_clone_options clone_options = GIT_CLONE_OPTIONS_INIT;
	git_checkout_options checkout_options = GIT_CHECKOUT_OPTIONS_INIT;
	git_fetch_options fetch_options = GIT_FETCH_OPTIONS_INIT;
	git_merge_options merge_options = GIT_MERGE_OPTIONS_INIT;

	git_index *merge_index = NULL;
	//git_oid head_id;
	git_commit *head_commit = NULL;
	//git_oid fetch_head_oid;
	git_commit *remote_commit = NULL;
	//git_oid merge_tree_id;
	//git_tree *merge_tree = NULL;
	//git_signature* signature = NULL;

	char temp[MAX_PATH];
	GetTempPathA(MAX_PATH, temp);
	std::string temp_path = std::string(temp) + folder;
	bool success = true;
	int error = 0;

	//git_index *index = NULL;
	//git_strarray paths = { nullptr, 0 };
	//paths.count = 1;
	//git_oid tree_oid, commit_oid;
	//const char *f = "*";
	//git_signature *signature = NULL;
	//git_tree *tree = NULL;
	//git_buf buffer;
	//
	//git_push_options options;

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

	if (git_repository_open(&repo, temp_path.c_str()) == 0) {

		if (success && git_remote_lookup(&remote, repo, "origin") != 0) {
			success = false;
		}

		fetch_options.callbacks.credentials = get_credentials;

		if (success && git_remote_fetch(remote, NULL, &fetch_options, "pull") != 0) {
			success = false;
		}
		/*if (success && git_reference_name_to_id(&head_id, repo, "HEAD") != 0) {
			success = false;
		}
		if (success && git_commit_lookup(&head_commit, repo, &head_id) != 0) {
			success = false;
		}
		if (success && git_reference_name_to_id(&fetch_head_oid, repo, "FETCH_HEAD") != 0) {
			success = false;
		}
		if (success && git_commit_lookup(&remote_commit, repo, &fetch_head_oid) != 0) {
			success = false;
		}
		if (success && git_merge_commits(&merge_index, repo, head_commit, remote_commit, &merge_options) != 0) {
			success = false;
		}*/

		/*if (git_index_has_conflicts(merge_index))
		{
			std::string satellite_path(git_repository_workdir(repo));
			std::string remote_path(git_remote_url(remote) + std::string("/"));
			merge_conflict_resolve(merge_index, satellite_path, remote_path);
		}*/

		/*if (success && git_index_write_tree_to(&merge_tree_id, merge_index, repo) != 0) {
			success = false;
		}*/

		/*if (success && git_tree_lookup(&merge_tree, repo, &merge_tree_id) != 0) {
			success = false;
		}*/

		/*checkout_options.checkout_strategy = GIT_CHECKOUT_SAFE;

		if (success && git_checkout_index(repo, merge_index, &checkout_options) != 0) {
			print_git_error(error);
			success = false;
		}*/
		/*if (success && git_signature_now(&signature, username.c_str(), email.c_str()) != 0) {
			success = false;
		}*/
		/*if (success && git_repository_state_cleanup(repo) != 0) {
			success = false;
		}*/
	}
	else {

		checkout_options.checkout_strategy = GIT_CHECKOUT_SAFE;
		clone_options.checkout_opts = checkout_options;
		clone_options.fetch_opts.callbacks.credentials = get_credentials;

		if (success && (error = git_clone(&repo, url.c_str(), temp_path.c_str(), &clone_options)) != 0) {
			print_git_error(error);
			success = false;
		}
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

	//git_buf_dispose(&buffer);

	/*if (signature) {
		git_signature_free(signature);
		signature = NULL;
	}

	if (merge_tree) {
		git_tree_free(merge_tree);
		merge_tree = NULL;
	}*/

	if (merge_index) {
		git_index_free(merge_index);
		merge_index = NULL;
	}

	if (remote_commit) {
		git_commit_free(remote_commit);
		remote_commit = NULL;
	}

	if (head_commit) {
		git_commit_free(head_commit);
		head_commit = NULL;
	}

	if (remote) {
		git_remote_free(remote);
		remote = NULL;
	}

	if (repo) {
		git_repository_free(repo);
		repo = NULL;
	}

	if (user) {
		SecureZeroMemory(user, sizeof(user));
		HeapFree(GetProcessHeap(), 0, user);
		user = NULL;
	}

	if (pass) {
		SecureZeroMemory(pass, sizeof(pass));
		HeapFree(GetProcessHeap(), 0, pass);
		pass = NULL;
	}

	return success;
}
