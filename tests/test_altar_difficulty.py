from pathlib import Path
import unittest

from server.assaultfire_room_registry import RoomRegistry

ROOT = Path(__file__).resolve().parents[1]


class AltarDifficultyTests(unittest.TestCase):
    def text(self, rel):
        return (ROOT / rel).read_text(encoding="utf-8", errors="replace")

    def test_a11e_is_an_active_handler(self):
        server = self.text("server/assaultfire_server_v143b.py")
        self.assertIn(
            "'name': 'OnlineRequest_SetGameSettings', 'cmd': 41246, "
            "'status': 'CURRENT_BRANCH'",
            server,
        )
        self.assertIn(
            'elif app["cmd"] == TGAME_ZN_REQ_SETGAMESETTINGS:',
            server,
        )
        self.assertIn("prepare_lobby_settings_update", server)
        self.assertIn("update_lobby_settings", server)

    def test_easy_normal_hard_pipeline_is_present(self):
        server = self.text("server/assaultfire_server_v143b.py")
        spawner = self.text("server/assaultfire_ds_spawner.py")
        loader = self.text(
            "tools/server_spawner/AFDevLoader_v48_spawner_multi_instance.py"
        )
        for submode, name in (
            ("0x00001001", "Easy"),
            ("0x00001002", "Normal"),
            ("0x00001003", "Hard"),
        ):
            self.assertIn(submode, server)
            self.assertIn(name, server)
        self.assertIn("--sub-mode-id", spawner)
        self.assertIn('("Easy", "Normal", "Hard")', loader)

    def test_shared_room_settings_change_to_hard(self):
        registry = RoomRegistry()
        easy_wire = bytes.fromhex(
            "00002001002f0000000100000010010000300800000000000000000000"
        )
        hard_wire = bytes.fromhex(
            "00002001002f0000000100000010030000300800000000000000000000"
        )
        room = registry.create_room(
            {
                "room_id": 1,
                "display_id": 1,
                "name": "The Altar",
                "match_settings_wire": easy_wire,
                "mode_id": 0x00002001,
                "map_id": 0x002F,
                "map_string": "",
                "sub_mode_id": 0x00001001,
                "flags": 0x00003008,
                "fighter_capacity": 4,
                "observer_capacity": 0,
                "password": "",
            },
            owner_uin=10001,
            owner_name="Owner",
        )
        self.assertEqual(room["sub_mode_id"], 0x00001001)

        room = registry.update_settings(
            1,
            match_settings_wire=hard_wire,
            mode_id=0x00002001,
            map_id=0x002F,
            map_string="",
            sub_mode_id=0x00001003,
            flags=0x00003008,
        )
        self.assertEqual(room["sub_mode_id"], 0x00001003)
        self.assertEqual(room["match_settings_wire"], hard_wire)


if __name__ == "__main__":
    unittest.main()
