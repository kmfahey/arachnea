#!/usr/bin/python3

import re

from arachnea.succeedfail import InternalException


class Handle:
    """
    Represents a mastodon handle.
    """
    __slots__ = 'handle_id', 'username', 'instance'

    handle_re = re.compile(r"^@[A-Za-z0-9_.-]+@[A-Za-z0-9.-]+\.[A-Za-z]+$")
    username_re = re.compile("^[A-Za-z0-9_.-]+$")
    instance_re = re.compile("^[A-Za-z0-9_.-]+\.[A-Za-z]+$")

    @property
    def handle_in_at_form(self):
        """
        Returns the handle in @username@instance form.
        """
        return f"@{self.username}@{self.instance}"

    @property
    def profile_url(self):
        """
        Returns the handle in https://instance/@username form.
        """
        return f"https://{self.instance}/@{self.username}"

    def __init__(self, handle_in_at_form='', handle_id=None, username='', instance=''):
        """
        Instances the Handle object.

        :param handle_id: The primary key of the row in the MySQL handles table that
                          furnished the data this Handle object is instanced from, if
                          any.
        :type handle_id:  int, optional
        :param username:  The part of the handle that represents the indicated user's
                          username.
        :type username:   str
        :param instance:  The part of the handle that represents the indicated user's
                          instance.
        :type instance:   str
        """
        if handle_in_at_form:
            if username or instance:
                match (bool(username), bool(instance)):
                    case (True, True):
                        raise InternalException("Handle object cannot be initialized from both a handle in @ form and "
                                                "also values for username and instance kwargs.")
                    case (True, False):
                        raise InternalException("Handle object cannot be initialized from both a handle in @ form and "
                                                "also a value for the username kwarg.")
                    case (False, True):
                        raise InternalException("Handle object cannot be initialized from both a handle in @ form and "
                                                "also a value for the instance kwarg.")
            self.username, self.instance = handle_in_at_form.strip('@').rsplit('@')
            self.handle_id = handle_id
        else:
            if handle_id is not None and not isinstance(handle_id, int):
                raise InternalException("handle_id argument must be an int")
            elif not isinstance(username, str) or not self.username_re.match(username):
                raise InternalException("username argument not a valid username: must be a str consisting of letters, "
                                        "numbers, periods, underscores, and dashes")
            elif not isinstance(instance, str) or not self.instance_re.match(instance):
                raise InternalException("instance argument not a valid instance: must be a str consisting of letters, "
                                        "numbers, periods, underscores, and dashes ending in a period followed by "
                                        "letters")
            self.handle_id = handle_id
            self.username = username
            self.instance = instance

    @classmethod
    def validate_handle(cls, handle):
        """
        Validates whether the handle argument matches the pattern for a valid mastodon
        handle. Returns True if so, False otherwise.

        :param handle: The string to validate whether it matches the pattern for a
                       mastodon handle or not.
        :type handle:  str
        :return:       True if the handle is a valid mastodon handle, False otherwise.
        :rtype:        bool
        """
        return bool(cls.handle_re.match(handle))

    def fetch_or_set_handle_id(self, data_store_obj):
        """
        If the Handle object was instanced from another source than a row in the
        MySQL handles table, set the handle_id from the table, inserting the data if
        necessary.

        :param data_store_obj: The Data_Store object to use to access the handles table.
        :type data_store_obj:  Data_Store
        :return:               True if the handle_id value was newly set; False if the
                               handle_id instance variable was already set.
        :rtype:                bool
        """
        # If the handle_id is already set, do nothing & return failure.
        if self.handle_id:
            return False

        # Fetch the extant handle_id value from the table if it so happens this
        # username/instance part is already in the handles table.
        fetch_handle_id_sql = f"""SELECT handle_id FROM handles WHERE username = '{self.username}'
                                                                AND instance = '{self.instance}';"""
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
                                                                AND instance = '{self.instance}';"""
        rows = data_store_obj.execute(fetch_handle_id_sql)
        if len(rows):
            return False

        data_store_obj.execute(f"""INSERT INTO handles (username, instance)
                                   VALUES ('{self.username}', '{self.instance}');""")
        return True


class DeletedUser(Handle):
    """
    Represents a user who has been deleted from their instance. Inherits from Handle.
    """
    __slots__ = 'logger_obj',

    @classmethod
    def fetch_all_deleted_users(cls, data_store_obj):
        """
        Retrieves all records from the deleted_users table and returns them in a dict.

        :param data_store_obj: The Data_Store object to use to contact the database.
        :type data_store_obj:  Data_Store
        :return:               A dict mapping 2-tuples of (username, instance) to
                               Deleted_User objects.
        :rtype:                dict
        """
        deleted_users_dict = dict()
        for row in data_store_obj.execute("SELECT handle_id, username, instance FROM deleted_users;"):
            handle_id, username, instance = row
            deleted_users_dict[username, instance] = DeletedUser(handle_id=handle_id, username=username,
                                                                 instance=instance)
        return deleted_users_dict

    @classmethod
    def from_handle_obj(cls, handle_obj):
        """
        Instances a Deleted_User object from the state of the Handle object argument.

        :return: A Deleted_User object.
        :rtype:  DeletedUser
        """
        return DeletedUser(handle_id=handle_obj.handle_id, username=handle_obj.username,
                           instance=handle_obj.instance)

    def save_deleted_user(self, data_store_obj):
        """
        Saves this deleted user to the deleted_users table.

        :param data_store_obj: The Data_Store object to use to contact the database.
        :type data_store_obj:  Data_Store
        :return:               False if the deleted user data is already present in the
                               deleted_users table, True otherwise.
        :rtype:                bool
        """
        if self.handle_id is None:
            self.fetch_or_set_handle_id(data_store_obj)
        select_sql = f"SELECT * FROM deleted_users WHERE handle_id = {self.handle_id};"
        if bool(len(data_store_obj.execute(select_sql))):
            return False
        insert_sql = f"""INSERT INTO deleted_users (handle_id, username, instance) VALUES
                         ({self.handle_id}, '{self.username}', '{self.instance}');"""
        data_store_obj.execute(insert_sql)
        self.logger_obj.info(f"inserted {self.handle_in_at_form} into table deleted_users")
        return True
