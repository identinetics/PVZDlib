import logging, os, shutil
import git
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
        self.rejectedpath = os.path.join(self.repo_dir_abs, GIT_REJECTED)
        self.requestedpath = os.path.join(self.repo_dir_abs, GIT_REQUESTQUEUE)
        self.deletedpath = os.path.join(self.repo_dir_abs, GIT_DELETED)
        self.publishedpath = os.path.join(self.repo_dir_abs, GIT_PUBLISHED)
        self.verbose = verbose

    def make_repo_dirs(self, repo_dir, pepout_dir=None):
        for p in (GIT_REQUESTQUEUE, GIT_DELETED, GIT_REJECTED, GIT_POLICYDIR, GIT_PUBLISHED):
            os.makedirs(os.path.join(repo_dir, p), exist_ok=True)
        if pepout_dir is not None:
            os.makedirs(pepout_dir, exist_ok=True)

    def getRequestQueueItems(self) -> str:
        """ :return: list of file names in the git repository given in pubreq  """
        return self.gitcmd.ls_files(GIT_REQUESTQUEUE).split('\n')

    def move_to_deleted(self, file):
        logging.debug('deleting file from accept directory ')
        file_to_delete = os.path.join(self.pepout_dir, file)
        if not os.path.exists(file_to_delete):
            raise ValidationError('rejected deletion request for non existing EntityDescriptor: '+ file)
        os.makedirs(self.deletedpath, exist_ok=True)
        shutil.move(file_to_delete, self.deletedpath)
        self.repo.index.add([os.path.join(self.deletedpath, os.path.basename(file))])
        # remove previously added ED in 'published'
        self.repo.index.remove([os.path.join(self.publishedpath, os.path.basename(file))])
        self.repo.index.commit('deleted')

    def move_to_published(self, file, sigdata):
        """ the accepted ED is (1) moved to 'published' and (2) copied to a directory for the aggregator
            that must be outside git to prevent any manipulation from a remote repo """
        logging.debug('moving to "published" path')
        with open(os.path.join(self.pepout_dir, os.path.basename(file)), mode='w', encoding='utf-8') as fd:
            fd.write(str(sigdata))
        file_abs = os.path.abspath(file)
        self.repo.index.move([file, self.publishedpath])
        self.repo.index.commit('accepted')

    def move_to_rejected(self, file):
        logging.debug('moving to reject directory ')
        self.repo.index.move([file, self.rejectedpath])

    def add_reject_message(self, filename_base, errortext):
        errfilename = os.path.join(self.rejectedpath, filename_base + '.err')
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
        repo.index.add([os.path.join(self.repo_dir_abs, '*')])
        repo.index.commit('initial testdata loaded')

    def add_request_message(self, filename):
        """ used for unit tests """
        base_fn = os.path.basename(filename)
        target_fn = os.path.join(self.repo_dir_abs, GIT_REQUESTQUEUE, base_fn)
        shutil.copyfile(filename, target_fn)
        self.repo.index.add([target_fn])
        self.repo.index.commit('add requested')
