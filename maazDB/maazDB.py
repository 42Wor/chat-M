import pickle
import os
import threading
import logging
from typing import Any, Dict, List

class maazDB:
    def __init__(self, filename="database.dm"):
        """
        Initialize the database with a .dm binary file format.
        :param filename: Name of the file to persist data.
        """
        self.filename = filename
        self.data: Dict[str, Any] = {}
        self.index: Dict[str, Dict[Any, List[str]]] = {}
        self.lock = threading.Lock()  # Lock for concurrency
        self._setup_logging # No need to pass the filename here
        self._load()

    def _setup_logging(self):
        pass
        """Set up logging for the database operations.
        logging.basicConfig(filename=f"{self.filename}.log", level=logging.INFO,
                            format="%(asctime)s - %(levelname)s - %(message)s")"""

    def _load(self):
        """ Load data from the .dm file in binary format. """
        if os.path.exists(self.filename):
            with open(self.filename, 'rb') as file:
                try:
                    self.data = pickle.load(file)
                    self.index = pickle.load(file)  # Load the index if exists
                    logging.info("Database loaded successfully.")
                except Exception as e:
                    logging.error(f"Error loading database: {e}")
                    self.data = {}
                    self.index = {}
        else:
            logging.info("No existing database found, starting fresh.")
            self.data = {}
            self.index = {}

    def _save(self):
        """ Save data to the .dm file in binary format. """
        try:
            with open(self.filename, 'wb') as file:
                pickle.dump(self.data, file)
                pickle.dump(self.index, file)
                logging.info("Database saved successfully.")
        except Exception as e:
            logging.error(f"Error saving database: {e}")

    def insert(self, key: str, value: Any):
        """
        Insert a new key-value pair into the database.
        :param key: The key to insert.
        :param value: The value associated with the key.
        """
        with self.lock:
            if key in self.data:
                logging.warning(f"Key '{key}' already exists.")
                raise KeyError(f"Key '{key}' already exists.")
            self.data[key] = value
            self._update_index(key, value)
            self._save()
            logging.info(f"Inserted key: {key}")

    def update(self, key: str, value: Any):
        """
        Update an existing key-value pair.
        :param key: The key to update.
        :param value: The new value to associate with the key.
        """
        with self.lock:
            if key not in self.data:
                logging.warning(f"Key '{key}' not found for update.")
                raise KeyError(f"Key '{key}' not found.")
            self.data[key] = value
            self._update_index(key, value)
            self._save()
            logging.info(f"Updated key: {key}")

    def get(self, key: str) -> Any:
        """
        Retrieve a value by key.
        :param key: The key to look up.
        :return: The associated value, or None if key doesn't exist.
        """
        return self.data.get(key, None)

    def delete(self, key: str):
        """
        Delete a key-value pair from the database.
        :param key: The key to delete.
        """
        with self.lock:
            if key in self.data:
                value = self.data.pop(key)
                self._update_index_after_deletion(key, value)
                self._save()
                logging.info(f"Deleted key: {key}")
            else:
                logging.warning(f"Key '{key}' not found for deletion.")
                raise KeyError(f"Key '{key}' not found.")

    def display_all(self) -> Dict[str, Any]:
        """ Return all data stored in the database. """
        return self.data

    def find_by_field(self, field: str, value: Any) -> List[Dict[str, Any]]:
        """
        Find all records where the field has a certain value.
        :param field: The field to search by (must be a key in the dictionary).
        :param value: The value to match for the given field.
        :return: A list of matching records.
        """
        result = []
        if field in self.index:
            matching_keys = self.index[field].get(value, [])
            result = [{key: self.data[key]} for key in matching_keys]
        return result

    def build_index(self, field: str):
        """
        Build an index for a specific field to optimize searching.
        :param field: The field to index.
        :return: A dictionary with values of the field as keys and lists of matching records.
        """
        index = {}
        for key, record in self.data.items():
            if isinstance(record, dict) and field in record:
                field_value = record[field]
                if field_value not in index:
                    index[field_value] = []
                index[field_value].append(key)
        self.index[field] = index
        self._save()
        logging.info(f"Built index for field: {field}")

    def _update_index(self, key: str, value: Any):
        """
        Update index after an insert or update.
        """
        for field in self.index:
            if isinstance(value, dict) and field in value:
                field_value = value[field]
                if field_value not in self.index[field]:
                    self.index[field][field_value] = []
                if key not in self.index[field][field_value]:
                    self.index[field][field_value].append(key)

    def _update_index_after_deletion(self, key: str, value: Any):
        """
        Update the index after a deletion.
        """
        for field in self.index:
            if isinstance(value, dict) and field in value:
                field_value = value[field]
                if field_value in self.index[field]:
                    self.index[field][field_value].remove(key)
                    if not self.index[field][field_value]:
                        del self.index[field][field_value]

    def query(self, condition: callable) -> List[Dict[str, Any]]:
        """
        Execute a query to find records that match a condition.
        :param condition: A lambda function to filter records.
        :return: A list of matching records.
        """
        return [record for record in self.data.values() if condition(record)]
