import pandas as pd
from repository import file_info_dict_template as fi


class View():
    def __init__(self, file_info_dicts):
        """
        The base class of repository views.
        This view can retrieve data from a repository based
        on one or more API queries, and results can be further filtered, searched and manipulated with methods of
        this class.

        1. A common View of repositories regardless of the source/search
        2. A View provides means to further filter and sort data.  For example,
        an object of this class can be initialized with a Search to the Malware Bazaar repository via a request
        for "the most recent 500 .exe files uploaded".  The data returned to this class can then be further
        filtered and searched to find those hashes matching multiple criteria (exes between a time span,
        with the tag: TrickBot, for example)
        3. The file info in views can be enriched with more data.  Examples:
        - Some Searches only return hashes of files.  Views can use other repository searches to retrieve more information at initialization or as needed
        - View file information can be enriched from the same or different source repositories using different Searches
        4. Helpers for analyzing the dataset of file information
        5. Managing the view's perspective
        - if the initial query asks for the first 50 data points returned by a API call, then a subsequent data retrieval ask would possibly, retrieve the next 50, or anything new since the last query
        6. Serialization into ... something... a file, csv table, database, a string, ... etc...

        Args:
            file_info_dicts: a list of Dict objects.  Each element represents file information

        """

        self._file_info_dicts = file_info_dicts
        self._dataframe = self._initialize()
        self._original_dataframe = self._dataframe
        self._iter_current_dataframe_row = 0

    def __iter__(self):
        self._iter_current_dataframe_row = 0
        return self

    def __len__(self):
        return len(self._dataframe.index)

    def __next__(self):
        count = len(self._dataframe.index)
        if self._iter_current_dataframe_row < count:
            sha256_hash = self._dataframe.iloc[self._iter_current_dataframe_row][fi.SHA256_HASH_KEY]
            result = fi.new_file_info_dict(
                sha256_hash=sha256_hash,
                first_seen=self.get_first_seen(sha256_hash),
                file_type=self.get_file_type(sha256_hash),
                file_name=self.get_file_name(sha256_hash),
                file_size=self.get_file_size(sha256_hash),
                file_ext=self.get_file_ext(sha256_hash),
                popular_threat_classification=self.get_file_classification(sha256_hash)
            )

            self._iter_current_dataframe_row += 1
            return result
        else:
            raise StopIteration

    def __str__(self):
        return self._dataframe.to_string()

    def get_by_key(self, file_hash, file_info_dict_key):
        """
        Generic get function to retrieve a property of a file via the property's key
        Args:
            file_hash: the file information to key on
            file_info_dict_key: accessible keys defined in file_info_dict_template... other keys are possible depending
            on the source of the information

        Returns:

        """
        values = self._dataframe.loc[self._dataframe[fi.SHA256_HASH_KEY] == file_hash, file_info_dict_key].iloc[0]
        return values

    def get_file_info(self, file_hash):
        record = self._dataframe.loc[self._dataframe[fi.SHA256_HASH_KEY] == file_hash].to_dict('records')
        return record[0]

    # TODO if these getters are called by Downloaders for information - we will need to make these thread safe
    def get_file_name(self, file_hash):
        """
        Override this method if there are pre-conditions that need to be met before file name property can be accessed.
        Proper subclassing of this would be:
        def get_file_name(self, file_hash):
            <do something and set the value>
            return super().get_file_name(self, file_hash)
        Args:
            file_hash: sha256 file hash

        Returns: the file name associated with this file hash

        """
        values = self._dataframe.loc[self._dataframe[fi.SHA256_HASH_KEY] == file_hash, fi.FILE_NAME_KEY].iloc[0]
        return values

    def set_file_name(self, file_hash, file_name):
        self._dataframe.loc[self._dataframe[fi.SHA256_HASH_KEY] == file_hash, fi.FILE_NAME_KEY] = file_name

    def get_file_size(self, file_hash):
        values = self._dataframe.loc[self._dataframe[fi.SHA256_HASH_KEY] == file_hash, fi.FILE_SIZE_KEY].iloc[0]
        return values

    def set_file_size(self, file_hash, file_size):
        self._dataframe.loc[self._dataframe[fi.SHA256_HASH_KEY] == file_hash, fi.FILE_SIZE_KEY] = file_size

    def get_file_type(self, file_hash):
        values = self._dataframe.loc[self._dataframe[fi.SHA256_HASH_KEY] == file_hash, fi.FILE_TYPE_KEY].iloc[0]
        return values

    def set_file_type(self, file_hash, file_type):
        self._dataframe.loc[self._dataframe[fi.SHA256_HASH_KEY] == file_hash, fi.FILE_TYPE_KEY] = file_type

    def get_file_ext(self, file_hash):
        values = self._dataframe.loc[self._dataframe[fi.SHA256_HASH_KEY] == file_hash, fi.FILE_EXT_KEY].iloc[0]
        return values

    def set_file_ext(self, file_hash, file_ext):
        self._dataframe.loc[self._dataframe[fi.SHA256_HASH_KEY] == file_hash, fi.FILE_EXT_KEY] = file_ext

    def get_file_classification(self, file_hash):
        values = self._dataframe.loc[self._dataframe[fi.SHA256_HASH_KEY] == file_hash, fi.POPULAR_THREAT_CLASSIFICATION].iloc[0]
        return values

    def set_file_classification(self, file_hash, popular_threat_classification):
        self._dataframe.loc[self._dataframe[fi.SHA256_HASH_KEY] == file_hash, fi.POPULAR_THREAT_CLASSIFICATION] = popular_threat_classification

    def get_first_seen(self, file_hash):
        values = self._dataframe.loc[self._dataframe[fi.SHA256_HASH_KEY] == file_hash, fi.FIRST_SEEN_KEY].iloc[0]
        return values

    def set_first_seen(self, file_hash, first_seen):
        self._dataframe.loc[self._dataframe[fi.SHA256_HASH_KEY] == file_hash, fi.FIRST_SEEN_KEY] = pd.to_datetime(
            first_seen)

    def empty(self):
        if self._dataframe.empty:
            return True
        else:
            return False

    def hashes(self):
        """
        Returns: a list of all hashes
        """
        if self._dataframe.empty:
            return []
        return self._dataframe[fi.SHA256_HASH_KEY].tolist()

    def filter_on_file_size(self, byte_size=1000000, size_operator='-'):
        """
        Filters the view by file size
        Args:
            byte_size: in bytes, defaults to 1000000 (1MB)
            size_operator: search for files smaller that byte_size, be default True.  If false, search for files larger than byte_size
        Returns:

        """
        if size_operator == '+':
            self._dataframe = self._dataframe[self._dataframe[fi.FILE_SIZE_KEY] > byte_size]
        elif size_operator == '-':
            self._dataframe = self._dataframe[self._dataframe[fi.FILE_SIZE_KEY] < byte_size]
        else:
            self._dataframe = self._dataframe[self._dataframe[fi.FILE_SIZE_KEY] == byte_size]

    def filter_on_first_seen(self, on_or_before=None, on_or_after=None):
        """
        Filters the view on before and after first_seen timestamp
        Args:
            on_or_before: time stamp string e.g. 2022-02-01.  If not supplied, will select the most recent date as the upper bound
            on_or_after: time stamp string e.g. 2022-01-01.  If not supplied, will select the oldest date as the lower bound
        Returns:

        """
        if not on_or_before:
            before_time = self._dataframe[fi.FIRST_SEEN_KEY].max()  # the newest entry
        else:
            before_time = pd.Timestamp(on_or_before)
        if not on_or_after:
            after_time = self._dataframe[fi.FIRST_SEEN_KEY].min()  # the oldest entry
        else:
            after_time = pd.Timestamp(on_or_after)

        self._dataframe = self._dataframe[(self._dataframe[fi.FIRST_SEEN_KEY] >= after_time) &
                                          (self._dataframe[fi.FIRST_SEEN_KEY] <= before_time)]

    def revert(self):
        """
        Revert back to the original dataset
        Returns: nothing

        """
        self._dataframe = self._original_dataframe

    def update(self, file_info_dict):
        """
        Update the View with file information dict.  File info dict supplied must have 'sha256_hash' key-value
        pair defined.  If sha256_hash does not yet exist in this view, it will be added along with the information
        supplied, if the sha256_hash already exists in this View, the information for this hash will be updated.

        Note: the revert() method will undo all update()s

        Args:
            file_info_dict: a dict in the format as described in file_info_dict_template.

        Returns: True, if update succeeds, False if hash is not supplied or update otherwise fails.
        """
        file_hash = file_info_dict[fi.SHA256_HASH_KEY]
        if not file_hash:
            return False

        exists = self._dataframe.loc[self._dataframe[fi.SHA256_HASH_KEY] == file_hash]
        if exists:
            self.set_file_name(file_hash, file_info_dict[fi.FILE_NAME_KEY])
            self.set_file_type(file_hash, file_info_dict[fi.FILE_TYPE_KEY])
            self.set_first_seen(file_hash, file_info_dict[fi.FIRST_SEEN_KEY])
            self.set_file_size(file_hash, file_info_dict[fi.FILE_SIZE_KEY])
            self.set_file_ext(file_hash, file_info_dict[fi.FILE_EXT_KEY])
            self.set_file_classification(file_hash, file_info_dict[fi.POPULAR_THREAT_CLASSIFICATION])
        else:
            self._dataframe = pd.concat([self._dataframe, file_info_dict])

        return True

    # ==============================
    # Serialization methods
    def to_csv(self):
        csv = ''
        for file_hash in self.hashes():
            csv += f'{file_hash},{self.get_file_name(file_hash)},{self.get_file_ext(file_hash)},' \
                   f'{self.get_first_seen(file_hash)},' \
                   f'{self.get_file_size(file_hash)},{self.get_file_type(file_hash)},' \
                   f'{self.get_file_classification(file_hash)}\n'
        return csv

    def to_file_info_dict(self):
        """

        Returns: a list of file infos (Dict objects of file info)

        """
        return self._dataframe.to_dict('records')

    def to_json(self):
        raise NotImplementedError

    def _initialize(self):
        df = pd.DataFrame(self._file_info_dicts)
        if fi.FIRST_SEEN_KEY in df:
            df[fi.FIRST_SEEN_KEY] = pd.to_datetime(df[fi.FIRST_SEEN_KEY], errors='coerce')
        if fi.LAST_SEEN_KEY in df:
            df[fi.LAST_SEEN_KEY] = pd.to_datetime(df[fi.LAST_SEEN_KEY], errors='coerce')

        return df

