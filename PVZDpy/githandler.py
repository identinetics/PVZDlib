import git
import logging
import os
from os.path import join
import shutil
from .constants import *
from .userexceptions import *
__author__ = 'r2h2'

class GitHandler:
    def __init__(self, repo_dir, pepout_dir, init=False, verbose=False):
        if init:
            shutil.rmtree(repo_dir, ignore_errors=True)
            self.make_repo_dirs(repo_dir, pepout_dir)
            self.repo = git.Repo.init(repo_dir)
        else:
            self.repo = git.Repo(repo_dir)
        self.gitcmd = git.Git(repo_dir)
        self.repo_dir = repo_dir
        self.repo_dir_abs = os.path.abspath(repo_dir)
        self.pepout_dir = pepout_dir
        self.rejectedpath = join(self.repo_dir_abs, GIT_REJECTED)
        self.requestedpath = join(self.repo_dir_abs, GIT_REQUESTQUEUE)
        self.unpublishpath = join(self.repo_dir_abs, GIT_DELETED)
        self.publishedpath = join(self.repo_dir_abs, GIT_PUBLISHED)
        self.verbose = verbose

    @staticmethod
    def make_repo_dirs(repo_dir):
        for p in (GIT_REQUESTQUEUE, GIT_DELETED, GIT_REJECTED, GIT_POLICYDIR, GIT_PUBLISHED):
            os.makedirs(join(repo_dir, p), exist_ok=True)

    def getRequestQueueItems(self) -> str:
        """ :return: list of file names in the git repository given in pubreq  """
        return self.gitcmd.ls_files(GIT_REQUESTQUEUE).split('\n')

    def move_to_deleted(self, request_name, publish_name):
        logging.debug('deleting file from published directory ')
        os.makedirs(self.unpublishpath, exist_ok=True)
        file_deleted = join(self.unpublishpath, publish_name)
        file_pepout = join(self.pepout_dir, publish_name)
        file_published = join(self.publishedpath, publish_name)
        file_requested = join(self.requestedpath, request_name)
        if not os.path.exists(file_pepout):
            raise ValidationError('rejected deletion request for non existing EntityDescriptor: '
                                  + file_pepout)
        self.gitcmd.mv(file_published, file_deleted)
        os.unlink(file_requested)
        os.unlink(file_pepout)
        self.repo.index.add([file_deleted])
        self.repo.index.commit('unpublished')

    def move_to_published_and_pepout(self, request_name, publish_name, sigdata):
        """ the accepted ED is (1) written to 'published' and (2)written to pepout for the
            aggregator to be outside git to prevent any manipulation from a remote repo.
            The published file has the canonical name of publish_name. The move is implemented as
            create + `git add` file at target location + `git rm` at original location.
        """
        publish_name = os.path.basename(publish_name)
        logging.debug('moving to published/' + publish_name)
        with open(join(self.pepout_dir, publish_name), mode='w', encoding='utf-8') as fd:
            fd.write(str(sigdata))
        with open(join(self.publishedpath, publish_name), mode='w', encoding='utf-8') as fd:
            fd.write(str(sigdata))
        os.unlink(join(self.requestedpath, request_name))
        self.repo.index.add([join(self.publishedpath, publish_name)])
        self.repo.index.commit('accepted')

    def move_to_rejected(self, request_name):
        logging.debug('moving to reject directory ')
        request_name = os.path.basename(request_name)
        file_requested = join(self.requestedpath, request_name)
        file_rejected = join(self.rejectedpath, request_name)
        self.gitcmd.mv([file_requested, file_rejected])

    def add_reject_message(self, request_name, errortext):
        errfilename = join(self.rejectedpath, request_name + '.err')
        with open(errfilename, 'w') as errorfile:
            errorfile.write(errortext)
        self.repo.index.add([errfilename])
        self.repo.index.commit('rejected')

    def reset_repo_with_defined_testdata(self, testdata):
        """  delete old, create empty repo and add data (used for unit testing) """
        shutil.rmtree(self.repo_dir, ignore_errors=True)
        shutil.copytree(testdata, self.repo_dir)
        self.make_repo_dirs(self.repo_dir) # add dirs not in test data
        repo = git.Repo.init(self.repo_dir)
        repo.index.add([join(self.repo_dir_abs, '*')])
        repo.index.commit('initial testdata loaded')

    def add_request_message(self, request_name):
        """ used for unit tests """
        base_fn = os.path.basename(request_name)
        target_fn = join(self.repo_dir_abs, GIT_REQUESTQUEUE, base_fn)
        shutil.copyfile(filename, target_fn)
        self.repo.index.add([target_fn])
        self.repo.index.commit('add requested')
