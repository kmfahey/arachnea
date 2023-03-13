#!/usr/bin/python3

import MySQLdb._exceptions


class Handle:
    """
    Represents a mastodon handle.
    """
    __slots__ = 'handle_id', 'username', 'host'

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
        # FIXME should do input checking on args
        assert isinstance(handle_id, int) or handle_id is None
        self.handle_id = handle_id
        self.username = username
        self.host = host

    def convert_to_deleted_user(self):
        """
        Instances a Deleted_User object from the state of this Handle object.

        :return: A Deleted_User object with the same values for its handle_id, username
                 and host state variables.
        :rtype:  Deleted_User
        """
        return Deleted_User(handle_id=self.handle_id, username=self.username, host=self.host)

    def fetch_or_set_handle_id(self, data_store):
        """
        If the Handle object was instanced from another source than a row in the
        MySQL handles table, set the handle_id from the table, inserting the data if
        necessary.

        :param data_store: The Data_Store object to use to access the handles table.
        :type data_store:  Data_Store
        :return:           True if the handle_id value was newly set; False if the
                           handle_id instance variable was already set.
        :rtype:            bool
        """
        # If the handle_id is already set, do nothing & return failure.
        if self.handle_id:
            return False

        # Fetch the extant handle_id value from the table if it so happens this
        # username/host part is already in the handles table.
        fetch_handle_id_sql = (f"""SELECT handle_id FROM handles WHERE username = '{self.username}'
                                                                 AND instance = '{self.host}';""")
        data_store.db_cursor.execute(fetch_handle_id_sql)
        rows = data_store.db_cursor.fetchall()

        # If it wasn't present, insert the username/host pair into the table,
        # and repeats the fetch query.
        if not len(rows):
            insert_handle_sql = f"INSERT INTO handles (username, instance) VALUES ('{self.username}', '{self.host}');"
            data_store.db_cursor.execute(insert_handle_sql)
            data_store.db_cursor.fetchall()
            data_store.db_cursor.execute(fetch_handle_id_sql)
            rows = data_store.db_cursor.fetchall()
        ((handle_id,),) = rows
        self.handle_id = handle_id
        return True


class Deleted_User(Handle):
    """
    Represents a user who has been deleted from their instance. Inherits from Handle.
    """
    __slots__ = 'logger_obj',

    @classmethod
    def fetch_all_deleted_users(self, data_store):
        # FIXME if the Handle and Deleted_User classes are made hashable then
        # the dict can be replaced with set.
        """
        Retrieves all records from the deleted_users table and returns them in a dict.

        :param data_store: The Data_Store object to use to contact the database.
        :type data_store:  Data_Store
        :return:           A dict mapping 2-tuples of (username, host) to Deleted_User
                           objects.
        :rtype:            dict
        """
        deleted_users_dict = dict()
        for row in data_store.execute("SELECT handle_id, username, instance FROM deleted_users;"):
            handle_id, username, host = row
            deleted_users_dict[username, host] = Deleted_User(handle_id=handle_id, username=username, host=host)
        return deleted_users_dict

    def save_deleted_user(self, data_store):
        # FIXME this code should check for the presence of the record in the
        # database rather than relying on an IntegrityError
        # FIXME should return True if successful, False if the record is already
        # present
        """
        Saves this deleted user to the deleted_users table.

        :param data_store: The Data_Store object to use to contact the database.
        :type data_store:  Data_Store
        :return:           None
        :rtype:            types.NoneType
        """
        insert_sql = f"""INSERT INTO deleted_users (handle_id, username, instance) VALUES
                         ({self.handle_id}, '{self.username}', '{self.host}');"""
        try:
            data_store.execute(insert_sql)
        except MySQLdb._exceptions.IntegrityError:
            self.logger_obj.info(f"got an SQL IntegrityError when inserting {self.handle} into table deleted_users")
        else:
            self.logger_obj.info(f"inserted {self.handle} into table deleted_users")
