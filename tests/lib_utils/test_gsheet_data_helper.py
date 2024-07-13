from src.lib_utils.gsheet import GSheetDataHelper, UpdateCellAction


class TestGSheetDataHelper:
    def get_helper(self):
        data = []
        header_row_index = 0
        key_column_name = "key"
        return GSheetDataHelper(data, header_row_index, key_column_name)

    def test_data_is_an_empty_list(self):
        helper = self.get_helper()
        assert helper.sheet_data == []

    def test_upsert_record_adds_headers(self):
        helper = self.get_helper()
        helper.upsert_record({"key": "value"})
        assert helper.sheet_data == [["key"], ["value"]]

    def test_upsert_record_generates_correct_actions(self):
        helper = self.get_helper()
        helper.upsert_record({"key": "value"})
        assert helper.actions == [
            UpdateCellAction(row=1, col=1, value="key"),
            UpdateCellAction(row=2, col=1, value="value"),
        ]

    def test_upsert_record_with_existing_records_adds_new_record(self):
        helper = self.get_helper()
        helper.upsert_record({"key": "value1"})
        helper.upsert_record({"key": "value2"})
        assert helper.sheet_data == [["key"], ["value1"], ["value2"]]

    def test_upsert_record_with_existing_records_adds_correct_actions(self):
        helper = self.get_helper()
        helper.upsert_record({"key": "value1"})
        helper.pop_actions()

        helper.upsert_record({"key": "value2"})
        assert helper.actions == [
            UpdateCellAction(row=3, col=1, value="value2"),
        ]

    def test_upsert_record_with_new_key_in_record_adds_new_column(self):
        helper = self.get_helper()
        helper.upsert_record({"key": "value1"})
        helper.upsert_record({"key": "value2", "new_key": "new_value"})
        assert helper.sheet_data == [
            ["key", "new_key"],
            ["value1"],
            ["value2", "new_value"],
        ]

    def test_upsert_record_with_new_key_in_record_adds_correct_actions(self):
        helper = self.get_helper()
        helper.upsert_record({"key": "value1"})
        helper.pop_actions()

        helper.upsert_record({"key": "value2", "new_key": "new_value"})
        assert helper.actions == [
            UpdateCellAction(row=1, col=2, value="new_key"),
            UpdateCellAction(row=3, col=1, value="value2"),
            UpdateCellAction(row=3, col=2, value="new_value"),
        ]

    def test_upsert_record_with_existing_key_in_record_updates_record(self):
        helper = self.get_helper()
        helper.upsert_record({"key": "value1", "a_data_column": "old_value"})
        assert helper.sheet_data == [
            ["key", "a_data_column"],
            ["value1", "old_value"],
        ]

        helper.upsert_record({"key": "value1", "a_data_column": "new_value"})
        assert helper.sheet_data == [
            ["key", "a_data_column"],
            ["value1", "new_value"],
        ]

    def test_pop_actions_returns_actions_and_clears_actions(self):
        helper = self.get_helper()
        helper.upsert_record({"key": "value1"})
        actions = helper.pop_actions()
        assert actions == [
            UpdateCellAction(row=1, col=1, value="key"),
            UpdateCellAction(row=2, col=1, value="value1"),
        ]
        assert helper.actions == []

    def test_data_is_always_stored_as_a_string(self):
        helper = self.get_helper()
        helper.upsert_record(
            {
                "key": 1,
                "a_bool": True,
                "a_float": 1.0,
                "a_list": [1, 2, 3, 4],
                "a_dict": {"a": 1},
                "a_none": None,
            }
        )
        assert helper.sheet_data == [
            ["key", "a_bool", "a_float", "a_list", "a_dict", "a_none"],
            ["1", "True", "1.0", "[1, 2, 3, 4]", "{'a': 1}", "None"],
        ]

    def test_key_is_always_compared_as_a_string_for_updates(self):
        helper = self.get_helper()
        helper.upsert_record({"key": 1, "data": "old"})
        helper.upsert_record({"key": "1", "data": "new"})
        assert helper.sheet_data == [
            ["key", "data"],
            ["1", "new"],
        ]


class TestGSheetDataHelperWithExistingData:
    def test_upsert_record_with_existing_data(self):
        data = [
            ["key", "data"],
            ["value1", "data1"],
        ]
        header_row_index = 0
        key_column_name = "key"
        helper = GSheetDataHelper(data, header_row_index, key_column_name)
        helper.upsert_record({"key": "value2", "data": "data2"})
        assert helper.sheet_data == [
            ["key", "data"],
            ["value1", "data1"],
            ["value2", "data2"],
        ]
