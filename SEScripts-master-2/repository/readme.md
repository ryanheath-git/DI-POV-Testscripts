# Repository module design

## Search (or  search.py)
Serves as a base abstraction on performing a search on a data source (repository API, database, file, etc).  

Future iterations of Search may include Search Pools, where the Search class manages multi-threaded searches with a Search Pool.

Concrete classes perform the search, parsing a common query format and formulating it into a query on a specific repository.

Search can be thought of as encapsulating logic for connecting and retrieving file information from a repository.

Search methods are used to run a query and return a View.

### Usage
Searches are created using the repository.factory method(s).  
A Search can be reused to run another search query - the result will be a new View

## View
A View can be thought of as a local representation of a repository, i.e. a "view", and a collection of information of files in that repository

The data a View contains is a set of information on a file or files, e.g. hash, first_seen, file_name, file_type, etc... 
for each file.   

Views are created with Search(es).  
- If the search simply queries for a hash, the View is just file information on that hash, if found.  
- If the Search queries for several hashes, the View is file information related to each hash that is found.
- If the Search uses a query (e.g. 'first_seen:2022-05-10+ type:pe'), then the View will contain file information on all hashes found (within limits). 

- Ideally, we will have normalized View for all repositories, i.e. the View's representation of file information will be consistent regardless of repository searched.

There are a few key reasons for this class:
1. A common View of repositories regardless of the source
2. A View provides means to further filter and sort data.  For example,
an object of this class can be initialized with a query to the Malware Bazaar repository via a request 
for "the most recent 500 .exe files uploaded".  The date returned to this class can then be further
filtered and searched to find those hashes matching multiple criteria (exes between a time span,
with the tag: TrickBot, for example)
3. The file info in views can be enriched with more data.  Examples:
- Some Searches only return hashes of files.  Views can use other repository searches to retrieve more information at initialization or as needed 
- View file information can be enriched from the same or different source repositories using different Searches
4. Helpers for analyzing the dataset of file information
5. Managing the view's perspective 
- if the initial query asks for the first 50 data points returned by a API call, then a subsequent data retrieval ask would possibly, retrieve the next 50, or anything new since the last query
6. Serialization into ... something... a file, csv table, database, a string, ... etc...

# Downloader
Provides a base class for handling file downloads.  Specific download details such as the api calls have to be handled 
within concrete classes. 