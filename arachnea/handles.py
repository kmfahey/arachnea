#!/usr/bin/python3

import re


class Handle:
    """
    Represents a mastodon handle.
    """
    __slots__ = 'handle_id', 'username', 'host'

    handle_re = re.compile(r"^@[A-Za-z0-9_.-]+@[A-Za-z0-9.-]+\.[A-Za-z0-9]+$")

    @property
    def handle(self):
        """
        Returns the handle in @username@host form.
        """
        return f"@{self.username}@{self.host}"

    @property
    def profile_url(self):
        """
        Returns the handle in https://host/@username form.
        """
        return f"https://{self.host}/@{self.username}"

    def __init__(self, handle_id=None, username='', host=''):
        """
        Instances the Handle object.

        :param handle_id: The primary key of the row in the MySQL handles table that
                          furnished the data this Handle object is instanced from, if
                          any.
        :type handle_id:  int, optional
        :param username:  The part of the handle that represents the indicated user's
                          username.
        :type username:   str
        :param host:      The part of the handle that represents the indicated user's
                          instance.
        :type host:       str
        """
        assert isinstance(handle_id, int) or handle_id is None
        self.handle_id = handle_id
        self.username = username
        self.host = host

    @classmethod
    def validate_handle(self, handle):
        """
        Validates whether the handle argument matches the pattern for a valid mastodon
        handle. Returns True if so, False otherwise.

        :param handle: The string to validate whether it matches the pattern for a
                       mastodon handle or not.
        :type handle:  str
        :return:       True if the handle is a valid mastodon handle, False otherwise.
        :rtype:        bool
        """
        return bool(self.handle_re.match(handle))

    def convert_to_deleted_user(self):
        """
        Instances a Deleted_User object from the state of this Handle object.

        :return: A Deleted_User object with the same values for its handle_id, username
                 and host state variables.
        :rtype:  Deleted_User
        """
        return Deleted_User(handle_id=self.handle_id, username=self.username, host=self.host)

    def fetch_or_set_handle_id(self, data_store_obj):
        """
        If the Handle object was instanced from another source than a row in the
        MySQL handles table, set the handle_id from the table, inserting the data if
        necessary.

        :param data_store_obj: The Data_Store object to use to access the handles table.
        :type data_store_obj:  Data_Store
        :return:           True if the handle_id value was newly set; False if the
                           handle_id instance variable was already set.
        :rtype:            bool
        """
        # If the handle_id is already set, do nothing & return failure.
        if self.handle_id:
            return False

        # Fetch the extant handle_id value from the table if it so happens this
        # username/host part is already in the handles table.
        fetch_handle_id_sql = f"""SELECT handle_id FROM handles WHERE username = '{self.username}'
                                                                AND instance = '{self.host}';"""
        rows = data_store_obj.execute(fetch_handle_id_sql)

        if not len(rows):
            self.save_handle(data_store_obj)

            rows = data_store_obj.execute(fetch_handle_id_sql)

        ((handle_id,),) = rows
        self.handle_id = handle_id
        return True

    def save_handle(self, data_store_obj):
        """
        Saves the handle to the handles table of the database. Returns False if this
        username and instance combination was already present in the handles table, True
        otherwise.

        :param data_store_obj: The Data_Store object to use to access the handles table.
        :type data_store_obj:  Data_Store
        :return:           False if the handle was already in the database, True
                           otherwise.
        :rtype:            bool
        """
        fetch_handle_id_sql = f"""SELECT handle_id FROM handles WHERE username = '{self.username}'
                                                                AND instance = '{self.host}';"""
        rows = data_store_obj.execute(fetch_handle_id_sql)
        if len(rows):
            return False

        data_store_obj.execute(f"INSERT INTO handles (username, instance) VALUES ('{self.username}', '{self.host}');")
        return True


class Deleted_User(Handle):
    """
    Represents a user who has been deleted from their instance. Inherits from Handle.
    """
    __slots__ = 'logger_obj',

    @classmethod
    def fetch_all_deleted_users(self, data_store_obj):
        """
        Retrieves all records from the deleted_users table and returns them in a dict.

        :param data_store_obj: The Data_Store object to use to contact the database.
        :type data_store_obj:  Data_Store
        :return:           A dict mapping 2-tuples of (username, host) to Deleted_User
                           objects.
        :rtype:            dict
        """
        deleted_users_dict = dict()
        for row in data_store_obj.execute("SELECT handle_id, username, instance FROM deleted_users;"):
            handle_id, username, host = row
            deleted_users_dict[username, host] = Deleted_User(handle_id=handle_id, username=username, host=host)
        return deleted_users_dict

    def save_deleted_user(self, data_store_obj):
        """
        Saves this deleted user to the deleted_users table.

        :param data_store_obj: The Data_Store object to use to contact the database.
        :type data_store_obj:  Data_Store
        :return:           False if the deleted user data is already present in the deleted_users table, True otherwise.
        :rtype:            bool
        """
        if self.handle_id is None:
            self.fetch_or_set_handle_id(data_store_obj)
        select_sql = f"SELECT * FROM deleted_users WHERE handle_id = {self.handle_id};"
        if bool(len(data_store_obj.execute(select_sql))):
            return False
        insert_sql = f"""INSERT INTO deleted_users (handle_id, username, instance) VALUES
                         ({self.handle_id}, '{self.username}', '{self.host}');"""
        data_store_obj.execute(insert_sql)
        self.logger_obj.info(f"inserted {self.handle} into table deleted_users")
        return True
