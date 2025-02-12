class RepositoryException(Exception):
    pass


class RepositoryDownloaderCreationError(RepositoryException):
    def __init__(self, message='Unable to create downloader repository due to missing arguments:', missing_args=None):
        self.message =  f'{message} {missing_args}'
        super().__init__(self.message)


class RepositorySearchCreationError(RepositoryException):
    def __init__(self, message='Unable to search repository due to missing arguments:', missing_args=None):
        self.message = f'{message} {missing_args}'
        super().__init__(self.message)


class FileDoesNotExistInRepository(RepositoryException):
    def __init__(self, message='Search of repository returned no results'):
        self.message = message
        super().__init__(self.message)


class SearchNotSupportedError(RepositoryException):
    def __init__(self, search, message='Search not supported'):
        """
        The search used is not supported by the repository being queried.
        Args:
            search:
            message:
        """
        self.search = search
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f'Search "{self.search}" not supported. {self.message}'


class NoResults(RepositoryException):
    def __init__(self, message='Search of repository returned no results'):
        self.message = message
        super().__init__(self.message)

