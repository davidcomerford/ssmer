import curses
import io
import math
import os
import signal
import socket
import tempfile
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from ssmer import (
    ACTIONS,
    Account,
    HEADER_ROWS,
    LIST_TOP,
    App,
    CONNECT,
    DEFAULT_LOCAL_PORT,
    DEFAULT_REMOTE_PORT,
    Forward,
    Instance,
    GREY_COLOR,
    KEYS_PLACEHOLDER,
    LOADING_FRAMES,
    NOT_MANAGED,
    NON_TERMINATED_STATES,
    platform_family,
    PORT_FORWARD,
    RADAR_COLORS,
    REGION_NAMES,
    REGION_PICKER_TOP,
    REGIONS,
    USER_SIGNALS,
    copy_to_clipboard,
    get_account,
    get_admin_password,
    get_instances,
    group_regions,
    find_key_files,
    fuzzy_match,
    list_key_directory,
    listening_ports,
    local_port_in_use,
    main,
    parse_args,
    radar_blips,
    radar_frame,
    region_choices,
    region_label,
    valid_port,
)


def make_instances(count):
    return [
        Instance(f"i-{n:03d}", f"host{n:03d}", "running", "t3.micro", f"10.0.0.{n}")
        for n in range(count)
    ]


def make_app(rows=24, columns=120):
    screen = MagicMock()
    screen.getmaxyx.return_value = (rows, columns)
    return screen, App(screen, None, None)


class PortValidationTests(unittest.TestCase):
    def test_default_remote_port_is_rdp(self):
        self.assertEqual(DEFAULT_REMOTE_PORT, "3389")

    def test_default_local_port(self):
        self.assertEqual(DEFAULT_LOCAL_PORT, "43389")

    @patch("ssmer.local_port_in_use", new=MagicMock(return_value=False))
    @patch("ssmer.curses.curs_set")
    def test_port_dialog_offers_the_rdp_defaults_and_restores_polling(self, _curs_set):
        screen, app = make_app()
        screen.getch.side_effect = [10, 10]  # Enter through both fields

        self.assertEqual(app.choose_ports(make_instances(1)[0]), ("3389", "43389"))
        self.assertEqual(screen.timeout.call_args_list[0], unittest.mock.call(-1))
        self.assertEqual(screen.timeout.call_args_list[-1], unittest.mock.call(200))

    @patch("ssmer.local_port_in_use", new=MagicMock(return_value=False))
    @patch("ssmer.subprocess.Popen")
    def test_forward_uses_the_ports_from_the_dialog(self, popen):
        screen, app = make_app()
        app.instances = [Instance("i-123", "windows", "running", "t3.large", "10.0.0.10")]
        app.choose_ports = MagicMock(return_value=("3390", "13389"))
        process = MagicMock()
        process.poll.return_value = None
        process.stdout = None
        popen.return_value = process

        self.assertTrue(app.start_forward(app.instances[0]))

        app.choose_ports.assert_called_once_with(app.instances[0])
        self.assertIn("portNumber=3390,localPortNumber=13389", popen.call_args.args[0])
        self.assertIn("13389", app.forwards)

    def test_supported_region_choices(self):
        self.assertEqual(REGIONS[:5], ("eu-west-1", "eu-west-2", "ap-southeast-2", "ap-northeast-1", "ap-northeast-3"))
        self.assertEqual(len(REGIONS), len(set(REGIONS)))
        self.assertIn("us-east-1", REGIONS)
        self.assertIn("mx-central-1", REGIONS)
        self.assertNotIn("cn-north-1", REGIONS)  # other partitions need their own credentials

    def test_accepts_ports_in_range(self):
        self.assertTrue(valid_port("1"))
        self.assertTrue(valid_port("65535"))

    def test_rejects_invalid_ports(self):
        for value in ("0", "65536", "http", "1.5"):
            self.assertFalse(valid_port(value))


class InstanceLoadingTests(unittest.TestCase):
    @patch("ssmer.subprocess.run")
    def test_reads_and_sorts_instances(self, run):
        run.return_value = MagicMock(
            returncode=0,
            stdout='{"Reservations":[{"Instances":[{"InstanceId":"i-b","InstanceType":"t3.micro","State":{"Name":"running"},"PrivateIpAddress":"10.0.0.2","Tags":[{"Key":"Name","Value":"beta"}]},{"InstanceId":"i-a","InstanceType":"t3.nano","State":{"Name":"stopped"},"Tags":[{"Key":"Name","Value":"Alpha"}]}]}]}',
        )
        instances = get_instances("dev", "eu-west-1")
        self.assertEqual([item.instance_id for item in instances], ["i-a", "i-b"])
        self.assertEqual(instances[1].private_ip, "10.0.0.2")
        self.assertEqual(instances[0].ssm_status, "Not managed")
        self.assertIn("--profile", run.call_args.args[0])

    @patch("ssmer.subprocess.run")
    def test_reads_ssm_ping_status(self, run):
        run.side_effect = [
            MagicMock(returncode=0, stdout='{"Reservations":[{"Instances":[{"InstanceId":"i-123","State":{"Name":"running"}}]}]}'),
            MagicMock(returncode=0, stdout='{"InstanceInformationList":[{"InstanceId":"i-123","PingStatus":"Online"}]}'),
        ]

        instances = get_instances(None, "eu-west-1")

        self.assertEqual(instances[0].ssm_status, "Online")
        self.assertIn("describe-instance-information", run.call_args_list[1].args[0])


class PlatformTests(unittest.TestCase):
    def test_windows_editions_are_windows(self):
        for details in ("Windows", "Windows with SQL Server Standard", "Windows BYOL"):
            self.assertEqual(platform_family({"PlatformDetails": details}), "Windows", details)

    def test_the_platform_field_alone_marks_windows(self):
        self.assertEqual(platform_family({"Platform": "windows"}), "Windows")

    def test_everything_else_is_linux(self):
        for details in ("Linux/UNIX", "Red Hat Enterprise Linux", "SUSE Linux", "Ubuntu Pro"):
            self.assertEqual(platform_family({"PlatformDetails": details}), "Linux", details)

    def test_no_platform_details_is_left_blank(self):
        self.assertEqual(platform_family({}), "")

    @patch("ssmer.subprocess.run")
    def test_instances_carry_their_platform(self, run):
        run.side_effect = [
            MagicMock(returncode=0, stdout='{"Reservations":[{"Instances":[{"InstanceId":"i-1","State":{"Name":"running"},"Platform":"windows","PlatformDetails":"Windows"},{"InstanceId":"i-2","State":{"Name":"running"},"PlatformDetails":"Linux/UNIX"}]}]}'),
            MagicMock(returncode=0, stdout='{"InstanceInformationList":[]}'),
        ]

        instances = get_instances(None, "eu-west-1")

        self.assertEqual([instance.platform for instance in instances], ["Windows", "Linux"])
        self.assertIn("Windows ", instances[0].label)


class InstancePresentationTests(unittest.TestCase):
    def test_label_includes_ssm_status(self):
        instance = Instance("i-123", "windows", "running", "t3.large", "10.0.0.10", "Online")

        self.assertIn("Online", instance.label)

    def test_stopped_instance_is_dimmed_in_table(self):
        screen = MagicMock()
        screen.getmaxyx.return_value = (24, 120)
        app = App(screen, None, None)
        app.instances = [Instance("i-123", "windows", "stopped", "t3.large", "10.0.0.10")]

        app.draw()

        row_call = next(call for call in screen.addnstr.call_args_list if call.args[:2] == (LIST_TOP, 2))
        self.assertTrue(row_call.args[4] & curses.A_DIM)


class SessionCheckTests(unittest.TestCase):
    @patch("ssmer.subprocess.run")
    def test_reads_the_account_and_its_alias(self, run):
        run.side_effect = [
            MagicMock(returncode=0, stdout='{"Account":"123456789012","Arn":"arn:aws:sts::123456789012:assumed-role/admin/dave"}'),
            MagicMock(returncode=0, stdout='{"AccountAliases":["acme-prod"]}'),
        ]

        account = get_account("dev", "eu-west-1")

        self.assertEqual(account, Account("123456789012", "arn:aws:sts::123456789012:assumed-role/admin/dave", "acme-prod"))
        self.assertEqual(account.label, "acme-prod (123456789012)")
        self.assertIn("get-caller-identity", run.call_args_list[0].args[0])

    @patch("ssmer.subprocess.run")
    def test_a_missing_alias_permission_only_warns(self, run):
        run.side_effect = [
            MagicMock(returncode=0, stdout='{"Account":"123456789012","Arn":"arn"}'),
            MagicMock(returncode=254, stdout="", stderr="AccessDenied"),
        ]
        warnings = []

        account = get_account(None, None, warnings.append)

        self.assertEqual(account.label, "123456789012")
        self.assertEqual(warnings, ["Account alias unavailable: AccessDenied"])

    @patch("ssmer.subprocess.run")
    def test_an_expired_session_raises(self, run):
        run.return_value = MagicMock(returncode=255, stdout="", stderr="Error loading SSO Token: Token has expired")

        with self.assertRaisesRegex(RuntimeError, "Token has expired"):
            get_account("dev", None)
        self.assertEqual(run.call_count, 1)

    @patch("ssmer.get_account", return_value=Account("123456789012", "arn", "acme-prod"))
    def test_account_is_shown_in_the_title(self, _get_account):
        screen, app = make_app()
        app.region = "eu-west-1"

        self.assertTrue(app.check_session())
        app.draw()

        drawn = {call.args[2] for call in screen.addnstr.call_args_list}
        self.assertIn("acme-prod (123456789012)", drawn)
        self.assertIn("eu-west-1", drawn)

    @patch("ssmer.get_account", side_effect=RuntimeError("Token has expired"))
    def test_quitting_from_the_session_error(self, get_account):
        screen, app = make_app()
        screen.getch.return_value = ord("q")

        self.assertFalse(app.check_session())
        self.assertIsNone(app.account)
        self.assertIn("Error: Token has expired", app.output)

    @patch("ssmer.get_account", side_effect=[RuntimeError("Token has expired"), Account("123456789012", "arn")])
    def test_retrying_after_logging_in(self, get_account):
        screen, app = make_app()
        screen.getch.return_value = ord("r")

        self.assertTrue(app.check_session())
        self.assertEqual(get_account.call_count, 2)
        self.assertEqual(app.account.account_id, "123456789012")


def named(*names):
    return [Instance(f"i-{n:03d}", name, "running", "t3.micro", "") for n, name in enumerate(names)]


class FuzzyMatchTests(unittest.TestCase):
    def test_characters_must_appear_in_order_ignoring_case(self):
        self.assertIsNotNone(fuzzy_match("PWb", "prod-web-01"))
        self.assertIsNone(fuzzy_match("bwp", "prod-web-01"))
        self.assertIsNone(fuzzy_match("web", ""))

    def test_an_empty_query_matches_everything(self):
        self.assertEqual(fuzzy_match("", "anything"), (0, []))

    def test_reports_the_matched_positions(self):
        self.assertEqual(fuzzy_match("web", "db-web-01")[1], [3, 4, 5])
        self.assertEqual(fuzzy_match("pw1", "prod-web-01")[1], [0, 5, 10])

    def test_prefers_the_tightest_match(self):
        # Matching the first "w" would leave a long gap before "b".
        self.assertEqual(fuzzy_match("wb", "west-web")[1], [5, 7])

    def test_contiguous_and_word_start_matches_rank_higher(self):
        self.assertGreater(fuzzy_match("web", "prod-web")[0], fuzzy_match("web", "wide-lab")[0])
        self.assertGreater(fuzzy_match("sw", "AppServerWindows")[0], fuzzy_match("sw", "answer")[0])


class SearchTests(unittest.TestCase):
    def type_keys(self, app, text):
        for char in text:
            app.handle_search_key(ord(char))

    @patch("ssmer.curses.curs_set")
    def test_typing_narrows_the_list_best_match_first(self, _curs_set):
        _, app = make_app()
        app.instances = named("db-west-web01", "dev-api", "prod-web-01", "web")
        app.start_search()

        self.type_keys(app, "web")

        self.assertEqual([i.name for i in app.shown], ["web", "prod-web-01", "db-west-web01"])
        self.assertEqual(app.selected, 0)

    @patch("ssmer.curses.curs_set")
    def test_backspace_widens_and_then_leaves_the_search(self, _curs_set):
        _, app = make_app()
        app.instances = named("alpha", "beta")
        app.start_search()
        self.type_keys(app, "al")

        app.handle_search_key(127)
        app.handle_search_key(127)
        self.assertEqual(len(app.shown), 2)
        self.assertTrue(app.searching)
        app.handle_search_key(127)
        self.assertFalse(app.searching)

    @patch("ssmer.curses.curs_set")
    def test_escape_clears_the_search(self, _curs_set):
        _, app = make_app()
        app.instances = named("alpha", "beta")
        app.start_search()
        self.type_keys(app, "zz")
        self.assertEqual(app.shown, [])

        app.handle_search_key(27)

        self.assertEqual((app.query, app.searching, len(app.shown)), ("", False, 2))

    @patch("ssmer.curses.curs_set")
    def test_enter_keeps_the_filter_and_acts_on_the_selected_match(self, _curs_set):
        _, app = make_app()
        app.instances = named("alpha", "beta", "gamma")
        app.start_search()
        self.type_keys(app, "a")
        app.handle_search_key(curses.KEY_DOWN)
        expected = app.shown[1]

        with patch.object(app, "choose_action", return_value=None) as choose_action:
            app.handle_search_key(10)

        choose_action.assert_called_once_with(expected)
        self.assertEqual(app.query, "a")
        self.assertFalse(app.searching)

    def test_j_and_k_are_typed_rather_than_moving(self):
        _, app = make_app()
        app.instances = named("jump", "kick")
        app.searching = True

        app.handle_search_key(ord("j"))

        self.assertEqual([i.name for i in app.shown], ["jump"])

    def test_matches_are_highlighted_in_the_name_column(self):
        screen, app = make_app()
        app.instances = named("prod-web-01")
        app.query = "pw"

        app.draw()

        highlighted = {(call.args[1], call.args[2]) for call in screen.addnstr.call_args_list
                       if call.args[0] == LIST_TOP and call.args[4] & app.match_attr == app.match_attr}
        self.assertEqual(highlighted, {(2, "p"), (7, "w")})  # inset inside the frame

    def test_says_when_nothing_matches(self):
        screen, app = make_app()
        app.instances = named("alpha")
        app.query = "zz"

        app.draw()

        self.assertIn("No instance names match “zz”.", [call.args[2] for call in screen.addnstr.call_args_list])

    def test_a_reload_refilters_with_the_current_search(self):
        _, app = make_app()
        app.query = "web"
        app.result_queue.put((app.load_generation, "ok", named("db", "web")))

        app.drain_load_results()

        self.assertEqual([i.name for i in app.shown], ["web"])

    @patch("ssmer.os.killpg")
    def test_disconnect_targets_the_selected_match(self, killpg):
        _, app = make_app()
        app.instances = named("alpha", "beta")
        app.query = "beta"
        process = MagicMock(pid=42)
        process.poll.return_value = None
        app.forwards["1"] = Forward(app.instances[1], "3389", "1", process)

        app.disconnect_selected()

        killpg.assert_called_once_with(42, signal.SIGTERM)


class DependencyCheckTests(unittest.TestCase):
    @patch("ssmer.subprocess.run")
    def test_runs_both_version_checks_and_records_output(self, run):
        run.return_value = MagicMock(returncode=0, stdout="version 1\n", stderr="")
        app = App(MagicMock(), None, None)
        app.check_dependencies()
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [["aws", "--version"], ["session-manager-plugin", "--version"]],
        )
        self.assertIn("$ aws --version", app.output)
        self.assertIn("version 1", app.output)


class DisconnectTests(unittest.TestCase):
    @patch("ssmer.os.killpg")
    def test_disconnect_stops_selected_instances_process_group(self, killpg):
        instance = Instance("i-123", "windows", "running", "t3.large", "10.0.0.10")
        process = MagicMock(pid=4321)
        process.poll.return_value = None
        app = App(MagicMock(), None, None)
        app.instances = [instance]
        app.forwards["13389"] = Forward(instance, "3389", "13389", process)

        app.disconnect_selected()

        killpg.assert_called_once_with(4321, signal.SIGTERM)
        self.assertTrue(any(line.startswith("Disconnected localhost:13389") for line in app.output))


def live_forward(local="13389", instance_id="i-123", connected=False, started=0.0):
    process = MagicMock(pid=4321)
    process.poll.return_value = None
    instance = Instance(instance_id, "windows", "running", "t3.large", "10.0.0.10")
    return Forward(instance, "3389", local, process, connected=connected, started=started)


class ForwardStatusTests(unittest.TestCase):
    def test_shows_active_forward_details(self):
        app = App(MagicMock(), None, None)
        app.forwards["13389"] = live_forward(connected=True)

        self.assertEqual(
            app.forward_status(),
            "STATUS: 1 connected — localhost:13389 → i-123:3389",
        )

    @patch("ssmer.time.monotonic", return_value=107.4)
    def test_a_running_process_is_only_connecting_until_the_port_opens(self, _monotonic):
        app = App(MagicMock(), None, None)
        app.forwards["13389"] = live_forward(started=100.0)

        self.assertEqual(
            app.forward_status(),
            "STATUS: 1 connecting — localhost:13389 → i-123:3389 (connecting 7s)",
        )

    @patch("ssmer.time.monotonic", return_value=103.0)
    def test_mixed_states_are_counted_separately(self, _monotonic):
        app = App(MagicMock(), None, None)
        app.forwards["13389"] = live_forward(connected=True)
        app.forwards["13390"] = live_forward("13390", "i-456", started=100.0)

        self.assertEqual(
            app.forward_status(),
            "STATUS: 1 connected, 1 connecting — localhost:13389 → i-123:3389, localhost:13390 → i-456:3389 (connecting 3s)",
        )

    def test_ignores_exited_forwards(self):
        instance = Instance("i-123", "windows", "running", "t3.large", "10.0.0.10")
        process = MagicMock()
        process.poll.return_value = 1
        app = App(MagicMock(), None, None)
        app.forwards["13389"] = Forward(instance, "3389", "13389", process)

        self.assertEqual(app.forward_status(), "STATUS: No active port forwards")

    def status_attr(self, *forwards):
        screen, app = make_app()
        app.active_status_attr, app.connecting_status_attr, app.disconnected_status_attr = 101, 303, 202
        for forward in forwards:
            app.forwards[forward.local_port] = forward

        app.draw()

        return next(call for call in screen.addnstr.call_args_list if call.args[0] == 16).args[4]

    def test_draws_active_status_with_active_colour(self):
        self.assertEqual(self.status_attr(live_forward(connected=True)), 101)

    def test_draws_connecting_status_with_connecting_colour(self):
        self.assertEqual(self.status_attr(live_forward()), 303)

    def test_one_connected_tunnel_is_enough_for_the_active_colour(self):
        self.assertEqual(self.status_attr(live_forward(connected=True), live_forward("13390")), 101)

    def test_draws_disconnected_status_with_disconnected_colour(self):
        screen = MagicMock()
        screen.getmaxyx.return_value = (24, 120)
        app = App(screen, None, None)
        app.active_status_attr = 101
        app.disconnected_status_attr = 202

        app.draw()

        status_call = next(call for call in screen.addnstr.call_args_list if call.args[0] == 16)
        self.assertEqual(status_call.args[4], 202)


class QuitConfirmationTests(unittest.TestCase):
    def test_confirm_quit_accepts_y_and_restores_polling(self):
        screen = MagicMock()
        screen.getmaxyx.return_value = (24, 120)
        screen.getch.return_value = ord("y")
        app = App(screen, None, None)

        self.assertTrue(app.confirm_quit())
        self.assertEqual(screen.timeout.call_args_list, [unittest.mock.call(-1), unittest.mock.call(200)])

    def test_confirm_quit_cancels_for_other_keys(self):
        screen = MagicMock()
        screen.getmaxyx.return_value = (24, 120)
        screen.getch.side_effect = [27, -1]  # a standalone Esc

        self.assertFalse(App(screen, None, None).confirm_quit())


class QuitButtonTests(unittest.TestCase):
    def active_app(self):
        screen, app = make_app()
        process = MagicMock(pid=4321)
        process.poll.return_value = None
        app.forwards["13389"] = Forward(make_instances(1)[0], "3389", "13389", process)
        return screen, app

    def test_enter_presses_the_focused_quit_button(self):
        screen, app = make_app()
        screen.getch.side_effect = [10]

        self.assertTrue(app.confirm_quit())

    def test_arrows_move_to_cancel(self):
        screen, app = make_app()
        screen.getch.side_effect = [curses.KEY_RIGHT, 10]

        self.assertFalse(app.confirm_quit())

    def test_focus_wraps_round_the_buttons(self):
        screen, app = make_app()
        screen.getch.side_effect = [curses.KEY_LEFT, curses.KEY_LEFT, 10]  # Cancel, then back to Quit

        self.assertTrue(app.confirm_quit())

    @patch("ssmer.os.killpg")
    def test_the_middle_button_disconnects_on_the_way_out(self, killpg):
        screen, app = self.active_app()
        screen.getch.side_effect = [curses.KEY_RIGHT, 10]

        self.assertTrue(app.confirm_quit())
        killpg.assert_called_once_with(4321, signal.SIGTERM)

    def test_the_focused_button_is_lit(self):
        screen, app = self.active_app()
        screen.getch.side_effect = [ord("\t"), 27, -1]

        app.confirm_quit()

        lit = [call.args[2] for call in screen.addnstr.call_args_list
               if call.args[2].startswith("[ ") and call.args[4] == curses.A_BOLD]
        self.assertEqual(lit, ["[ Quit ]", "[ Quit + disconnect ]"])  # before and after Tab


class RegionChoiceTests(unittest.TestCase):
    def test_region_outside_the_built_in_list_is_still_offered(self):
        self.assertEqual(region_choices("cn-north-1"), ("cn-north-1", *REGIONS))

    def test_built_in_and_missing_regions_leave_the_list_alone(self):
        self.assertEqual(region_choices("eu-west-2"), REGIONS)
        self.assertEqual(region_choices(None), REGIONS)

    def test_configured_regions_replace_the_built_in_list(self):
        self.assertEqual(region_choices(None, "us-east-1, us-west-2,"), ("us-east-1", "us-west-2"))
        self.assertEqual(region_choices("eu-west-1", "us-east-1"), ("eu-west-1", "us-east-1"))
        self.assertEqual(region_choices(None, " , "), REGIONS)

    def test_the_app_reads_configured_regions_from_the_environment(self):
        with patch.dict(os.environ, {"SSMER_REGIONS": "us-east-1,us-east-2"}):
            _, app = make_app()
        self.assertEqual(app.regions, ("us-east-1", "us-east-2"))

    def test_picker_preselects_a_region_supplied_on_the_command_line(self):
        screen = MagicMock()
        screen.getmaxyx.return_value = (24, 120)
        screen.getch.return_value = 10  # Enter, without moving the cursor
        app = App(screen, None, "us-east-1")

        self.assertTrue(app.select_region())
        self.assertEqual(app.region, "us-east-1")

    def picker(self, keys, rows=24, region=None):
        screen = MagicMock()
        screen.getmaxyx.return_value = (rows, 120)
        screen.getch.side_effect = [*keys, -1]  # -1 ends each Esc as a standalone key
        return screen, App(screen, None, region)

    def drawn(self, screen):
        return [call.args for call in screen.addnstr.call_args_list]

    def test_picker_scrolls_to_regions_below_the_fold(self):
        screen, app = self.picker([ord("j")] * (len(REGIONS) - 1) + [10], rows=10)  # room for five rows

        self.assertTrue(app.select_region())
        self.assertEqual(app.region, "me-south-1")  # the last of the last group
        last_frame = self.drawn(screen)[-12:]
        self.assertTrue(any(args[:3] == (9, 4, region_label("me-south-1", 14)) and args[4] == curses.A_REVERSE for args in last_frame))

    def test_picker_lists_place_names_under_headings(self):
        screen, app = self.picker([10])

        self.assertTrue(app.select_region())
        self.assertEqual(app.region, "eu-west-1")  # the first favourite
        texts = [args[2] for args in self.drawn(screen)]
        self.assertIn("Favourites", texts)
        self.assertIn("Europe", texts)
        self.assertIn(region_label("eu-west-1", 14), texts)

    def test_picker_search_matches_place_names(self):
        screen, app = self.picker([ord("/"), *map(ord, "tokyo"), 10])

        self.assertTrue(app.select_region())
        self.assertEqual(app.region, "ap-northeast-1")

    def test_picker_search_takes_the_navigation_letters_as_text(self):
        screen, app = self.picker([ord("/"), *map(ord, "jakarta"), 10])

        self.assertTrue(app.select_region())
        self.assertEqual(app.region, "ap-southeast-3")

    def test_esc_clears_the_search_and_keeps_the_match_highlighted(self):
        screen, app = self.picker([ord("/"), *map(ord, "ohio"), 27, -1, 10])

        self.assertTrue(app.select_region())
        self.assertEqual(app.region, "us-east-2")

    def test_enter_with_no_matches_does_nothing(self):
        screen, app = self.picker([ord("/"), *map(ord, "zzz"), 10, 27, -1, ord("q")])

        self.assertFalse(app.select_region())
        self.assertIn((REGION_PICKER_TOP, 2, "No regions match “zzz”.", 117, curses.A_NORMAL), self.drawn(screen))

    def test_regions_are_grouped_with_favourites_first(self):
        groups = group_regions(("us-gov-west-1", "us-east-1", "eu-central-1", "eu-west-1", "af-south-1"))
        self.assertEqual(groups, [
            ("Favourites", ["eu-west-1"]),
            ("Europe", ["eu-central-1"]),
            ("Americas", ["us-east-1"]),
            ("Middle East & Africa", ["af-south-1"]),
            ("Other", ["us-gov-west-1"]),
        ])

    def test_every_built_in_region_has_a_place_name(self):
        self.assertEqual(set(REGION_NAMES), set(REGIONS))
        self.assertEqual(region_label("us-east-1", 14), "us-east-1       N. Virginia")
        self.assertEqual(region_label("us-gov-west-1", 14), "us-gov-west-1")


class AccountIdentityTests(unittest.TestCase):
    def identity(self, arn):
        return Account("123456789012", arn).identity

    def test_an_iam_user_keeps_its_type(self):
        self.assertEqual(self.identity("arn:aws:iam::123456789012:user/dave"), "user/dave")

    def test_an_assumed_role_shows_role_and_session(self):
        self.assertEqual(self.identity("arn:aws:sts::123456789012:assumed-role/admin/dave"), "admin/dave")

    def test_an_identity_center_role_shows_its_permission_set(self):
        arn = "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_AdministratorAccess_3f9c1a2b4d5e6f70/dave@example.com"
        self.assertEqual(self.identity(arn), "AdministratorAccess/dave@example.com")

    def test_the_root_user_and_odd_arns_pass_through(self):
        self.assertEqual(self.identity("arn:aws:iam::123456789012:root"), "root")
        self.assertEqual(self.identity("arn"), "arn")


class HeaderTests(unittest.TestCase):
    def drawn(self, screen):
        return {call.args[2] for call in screen.addnstr.call_args_list}

    def test_header_shows_context_beside_the_key_grid(self):
        screen, app = make_app()
        app.profile = "prod-admin"
        app.region = "eu-west-2"

        app.draw()

        rows = {(call.args[0], call.args[2]) for call in screen.addnstr.call_args_list}
        self.assertTrue({(0, "Account:"), (1, "Profile:"), (2, "Region:")} <= rows)
        self.assertTrue({(1, "prod-admin"), (2, "eu-west-2")} <= rows)
        self.assertTrue({(0, "<Enter>"), (0, "Connect/Forward"), (2, "<q>"), (2, "Quit")} <= rows)

    def test_the_key_grid_switches_to_search_keys_while_typing(self):
        screen, app = make_app()
        app.instances = named("prod-web-01", "build")
        app.searching = True
        app.set_query("pw")

        app.draw()

        self.assertTrue({"<↑/↓>", "Move", "<Esc>", "Clear"} <= self.drawn(screen))
        self.assertNotIn("Connect/Forward", self.drawn(screen))
        self.assertIn(" </pw> ", self.drawn(screen))
        self.assertIn("[1/2] ", self.drawn(screen))

    def test_the_caret_sits_after_the_query_in_the_frame_title(self):
        screen, app = make_app()
        app.searching = True
        app.set_query("pw")

        app.draw()

        query = next(call for call in screen.addnstr.call_args_list if call.args[2] == " </pw> ")
        screen.move.assert_called_with(HEADER_ROWS, query.args[1] + len(" </pw"))

    def test_identity_sits_under_region(self):
        screen, app = make_app()
        app.account = Account("123456789012", "arn:aws:sts::123456789012:assumed-role/admin/dave")

        app.draw()

        rows = {(call.args[0], call.args[2]) for call in screen.addnstr.call_args_list}
        self.assertTrue({(3, "Identity:"), (3, "admin/dave")} <= rows)

    def test_long_context_is_shortened_before_key_columns_go(self):
        screen, app = make_app()
        app.account = Account("123456789012", "arn:aws:iam::123456789012:user/" + "x" * 80)

        app.draw()

        self.assertIn("Disconnect all", self.drawn(screen))
        identity = next(text for text in self.drawn(screen) if text.startswith("user/x"))
        self.assertTrue(identity.endswith("…"))

    def test_a_narrow_terminal_drops_whole_key_columns(self):
        screen, app = make_app(rows=24, columns=50)

        app.draw()

        self.assertIn("Connect/Forward", self.drawn(screen))
        self.assertNotIn("Disconnect all", self.drawn(screen))

    def test_the_key_grid_is_flush_with_the_frames_right_edge(self):
        screen, app = make_app()  # 120 columns: the frame's right edge is column 118

        app.draw()

        widest = next(call for call in screen.addnstr.call_args_list if call.args[2] == "Disconnect all")
        self.assertEqual(widest.args[1] + len("Disconnect all"), 118)


class ViewportTests(unittest.TestCase):
    def test_list_scrolls_only_when_the_selection_leaves_the_view(self):
        screen, app = make_app()
        app.instances = make_instances(40)

        app.selected = 20
        app.draw()
        self.assertEqual(app.top, 12)  # 9 rows visible, the selection on the last

        app.selected = 15  # still on screen, so the list must not move
        app.draw()
        self.assertEqual(app.top, 12)

        app.selected = 8  # off the top, so the list follows by a single row
        app.draw()
        self.assertEqual(app.top, 8)

    def test_first_visible_row_matches_the_scroll_offset(self):
        screen, app = make_app()
        app.instances = make_instances(40)
        app.selected = 20

        app.draw()

        first_row = next(call for call in screen.addnstr.call_args_list if call.args[:2] == (LIST_TOP, 2))
        self.assertTrue(first_row.args[2].startswith("host012"))

    def test_short_list_never_scrolls(self):
        screen, app = make_app()
        app.instances = make_instances(3)
        app.selected = 2

        app.draw()

        self.assertEqual(app.top, 0)


class SmallTerminalTests(unittest.TestCase):
    def test_draw_survives_a_terminal_too_small_for_the_layout(self):
        screen, app = make_app(rows=3, columns=12)
        screen.addnstr.side_effect = curses.error
        app.instances = make_instances(5)

        app.draw()

        rows = [call.args[0] for call in screen.addnstr.call_args_list]
        self.assertTrue(rows)
        self.assertTrue(all(0 <= row < 3 for row in rows))

    def test_confirm_quit_survives_a_tiny_terminal(self):
        screen, app = make_app(rows=3, columns=12)
        screen.addnstr.side_effect = curses.error
        screen.getch.return_value = ord("y")

        self.assertTrue(app.confirm_quit())


class ForwardReapingTests(unittest.TestCase):
    def test_reports_a_forward_that_exited_on_its_own(self):
        screen, app = make_app()
        process = MagicMock(pid=4321)
        process.poll.return_value = 255
        app.forwards["13389"] = Forward(make_instances(1)[0], "3389", "13389", process)

        app.update_forwards()

        self.assertTrue(any("exit status 255" in line for line in app.output))
        self.assertIn("failed to connect", app.message)

    def test_an_exit_is_only_reported_once(self):
        screen, app = make_app()
        process = MagicMock(pid=4321)
        process.poll.return_value = 255
        app.forwards["13389"] = Forward(make_instances(1)[0], "3389", "13389", process)

        app.update_forwards()
        app.output.clear()
        app.update_forwards()

        self.assertEqual(list(app.output), [])

    @patch("ssmer.os.killpg")
    def test_a_deliberate_disconnect_is_not_reported_a_second_time(self, _killpg):
        screen, app = make_app()
        instance = make_instances(1)[0]
        process = MagicMock(pid=4321)
        process.poll.return_value = None
        app.instances = [instance]
        app.forwards["13389"] = Forward(instance, "3389", "13389", process)

        app.disconnect_selected()
        process.poll.return_value = 0
        app.output.clear()
        app.update_forwards()

        self.assertEqual(list(app.output), [])


class ForwardConnectionTests(unittest.TestCase):
    def watch(self, text, forward=None):
        screen, app = make_app()
        forward = forward or live_forward()
        app.watch_output(io.StringIO(text), forward)
        return app, forward

    def test_starting_the_session_is_not_yet_connected(self):
        app, forward = self.watch("\nStarting session with SessionId: dev-0abc\n")

        self.assertFalse(forward.connected)

    def test_the_plugin_opening_the_port_marks_it_connected(self):
        for line in ("Port 13389 opened for sessionId dev-0abc.", "Waiting for connections..."):
            app, forward = self.watch(f"Starting session with SessionId: dev-0abc\n{line}\n")

            self.assertTrue(forward.connected, line)

    def test_output_still_reaches_the_panel(self):
        app, forward = self.watch("Waiting for connections...\n")
        app.drain_output()

        self.assertIn("[13389 → i-123] Waiting for connections...", app.output)

    def test_connecting_is_announced_once(self):
        screen, app = make_app()
        app.forwards["13389"] = live_forward(connected=True)

        app.update_forwards()
        self.assertEqual(app.message, "Connected localhost:13389 → i-123:3389.")
        app.output.clear()
        app.message = ""
        app.update_forwards()

        self.assertEqual((list(app.output), app.message), ([], ""))

    def test_an_exit_before_connecting_is_a_failure_with_its_reason(self):
        screen, app = make_app()
        forward = live_forward()
        forward.last_line = "An error occurred (TargetNotConnected) when calling the StartSession operation"
        forward.process.poll.return_value = 254
        app.forwards["13389"] = forward

        app.update_forwards()

        self.assertEqual(
            app.message,
            "localhost:13389 → i-123:3389 failed to connect (exit status 254): "
            "An error occurred (TargetNotConnected) when calling the StartSession operation",
        )

    def test_an_exit_after_connecting_is_a_disconnect(self):
        screen, app = make_app()
        forward = live_forward(connected=True)
        forward.connect_reported = True
        forward.process.poll.return_value = 0
        app.forwards["13389"] = forward

        app.update_forwards()

        self.assertEqual(app.message, "localhost:13389 → i-123:3389 disconnected (exit status 0).")
        self.assertEqual(app.forward_status(), "STATUS: No active port forwards")

    def test_the_final_output_is_read_before_the_exit_is_explained(self):
        screen, app = make_app()
        forward = live_forward()
        forward.process.poll.return_value = 254
        forward.watcher = MagicMock()
        forward.watcher.join.side_effect = lambda timeout: setattr(forward, "last_line", "late error")
        app.forwards["13389"] = forward

        app.update_forwards()

        forward.watcher.join.assert_called_once_with(timeout=0.5)
        self.assertTrue(app.message.endswith(": late error"))


class LocalPortTests(unittest.TestCase):
    def test_a_port_with_a_listener_is_in_use(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]

        self.assertTrue(local_port_in_use(port))
        listener.close()
        self.assertFalse(local_port_in_use(port))

    def test_listening_ports_reads_only_listen_rows_from_both_tables(self):
        header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        tcp = header + (
            "   0: 0100007F:A97D 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 0 1 1\n"  # 43389, LISTEN
            "   1: 0100007F:1F90 0100007F:D2A4 01 00000000:00000000 00:00000000 00000000  1000 0 2 1\n"  # 8080, ESTABLISHED
        )
        tcp6 = header + "   0: 00000000000000000000000001000000:0CEA 00000000000000000000000000000000:0000 0A 0 0 0 0 0 3 1\n"
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for name, text in (("tcp", tcp), ("tcp6", tcp6)):
                paths.append(os.path.join(directory, name))
                with open(paths[-1], "w") as table:
                    table.write(text)

            self.assertEqual(listening_ports(paths), {43389, 3306})

    def test_no_proc_means_unknown_rather_than_nothing_listening(self):
        self.assertIsNone(listening_ports(("/nonexistent/tcp", "/nonexistent/tcp6")))

    @patch("ssmer.curses.curs_set")
    @patch("ssmer.local_port_in_use", return_value=True)
    def test_a_port_that_is_taken_is_refused_in_the_dialog(self, _in_use, _curs_set):
        screen, app = make_app()
        screen.getch.side_effect = [10, 10, 27, -1]  # accept both defaults, then give up

        self.assertIsNone(app.choose_ports(make_instances(1)[0]))
        drawn = [call.args[2] for call in screen.addnstr.call_args_list]
        self.assertTrue(any("localhost:43389 is in use by another program" in text for text in drawn))


class ForwardListenerTests(unittest.TestCase):
    def update(self, listening, now=101.0, forward=None):
        screen, app = make_app()
        forward = forward or live_forward(started=100.0)
        app.forwards[forward.local_port] = forward
        with patch("ssmer.listening_ports", return_value=listening), patch("ssmer.time.monotonic", return_value=now):
            app.update_forwards()
        return app, forward

    def test_the_port_listening_marks_the_tunnel_connected(self):
        app, forward = self.update({13389})

        self.assertTrue(forward.connected)
        self.assertEqual(app.message, "Connected localhost:13389 → i-123:3389.")

    def test_other_listening_ports_do_not_count(self):
        app, forward = self.update({3389, 43389})

        self.assertFalse(forward.connected)

    def test_without_proc_the_plugin_output_is_the_only_signal(self):
        app, forward = self.update(None)

        self.assertFalse(forward.connected)

    def test_a_tunnel_still_connecting_after_the_limit_is_called_out_once(self):
        forward = live_forward(started=100.0)
        forward.last_line = "Starting session with SessionId: dev-0abc"

        app, _ = self.update(set(), now=100.0 + 30, forward=forward)
        self.assertEqual(
            app.message,
            "localhost:13389 → i-123:3389 still not connected after 30s; d cancels it. "
            "Last output: Starting session with SessionId: dev-0abc",
        )
        app.message = ""
        with patch("ssmer.listening_ports", return_value=set()), patch("ssmer.time.monotonic", return_value=145.0):
            app.update_forwards()

        self.assertEqual(app.message, "")

    def test_no_warning_before_the_limit(self):
        app, forward = self.update(set(), now=100.0 + 29)

        self.assertFalse(forward.slow_reported)
        self.assertNotIn("still not connected", app.message)


class DisconnectAllTests(unittest.TestCase):
    @patch("ssmer.os.killpg")
    def test_reaches_forwards_whose_instance_is_no_longer_listed(self, killpg):
        screen, app = make_app()
        first, second = make_instances(2)
        for pid, (port, instance) in enumerate((("13389", first), ("13390", second)), start=100):
            process = MagicMock(pid=pid)
            process.poll.return_value = None
            app.forwards[port] = Forward(instance, "3389", port, process)
        app.instances = []  # e.g. after switching to a different region

        self.assertEqual(app.disconnect_all(), 2)
        self.assertEqual(sorted(call.args[0] for call in killpg.call_args_list), [100, 101])

    def test_reports_when_there_is_nothing_to_disconnect(self):
        screen, app = make_app()

        self.assertEqual(app.disconnect_all(), 0)
        self.assertEqual(app.message, "No active port forwards to disconnect.")

    @patch("ssmer.os.killpg", side_effect=ProcessLookupError("gone"))
    def test_a_process_that_already_exited_is_not_called_disconnected(self, _killpg):
        screen, app = make_app()
        process = MagicMock(pid=4321)
        process.poll.return_value = None
        app.forwards["13389"] = Forward(make_instances(1)[0], "3389", "13389", process)

        app.disconnect_all()

        self.assertTrue(any(line.startswith("Could not stop") for line in app.output))
        self.assertFalse(any(line.startswith("Disconnected") for line in app.output))


@patch("ssmer.local_port_in_use", new=MagicMock(return_value=False))
@patch("ssmer.curses.curs_set", new=MagicMock())
class PortDialogTests(unittest.TestCase):
    def choose(self, keys, app=None):
        screen, app = make_app() if app is None else (app.screen, app)
        screen.getch.side_effect = keys
        return app.choose_ports(make_instances(1)[0])

    def test_escape_cancels(self):
        self.assertIsNone(self.choose([27, -1]))  # Esc, with nothing following it

    def test_escape_cancels_after_something_has_been_typed(self):
        self.assertIsNone(self.choose([ord("1"), ord("3"), 27, -1]))

    def test_typing_replaces_the_default(self):
        self.assertEqual(self.choose([*b"22", 10, *b"2222", 10]), ("22", "2222"))

    def test_backspace_edits_the_default(self):
        self.assertEqual(self.choose([curses.KEY_BACKSPACE, ord("0"), 10, 10]), ("3380", "43389"))

    def test_tab_and_arrows_switch_fields(self):
        self.assertEqual(self.choose([9, *b"1", curses.KEY_UP, *b"2", curses.KEY_DOWN, 10]), ("2", "1"))

    def test_an_arrow_key_does_not_cancel(self):
        # An unparsed arrow arrives as Esc [ B; only a lone Esc means cancel.
        self.assertEqual(self.choose([27, ord("["), ord("B"), -1, 10, 10]), ("3389", "43389"))

    def test_only_digits_are_accepted_up_to_five(self):
        self.assertEqual(self.choose([*b"8x0", 10, *b"1234567", 10]), ("80", "12345"))

    def test_an_invalid_port_keeps_the_dialog_open_on_that_field(self):
        screen, app = make_app()
        # Remote 0 is refused; the dialog returns to the remote field to fix it.
        result = self.choose([*b"0", 10, 10, curses.KEY_BACKSPACE, *b"22", 10, 10], app)

        self.assertEqual(result, ("22", "43389"))
        drawn = [call.args[2] for call in screen.addnstr.call_args_list]
        self.assertTrue(any("The remote port must be from 1 through 65535." in text for text in drawn))

    def test_leading_zeros_are_dropped(self):
        self.assertEqual(self.choose([*b"00022", 10, 10]), ("22", "43389"))

    def test_a_live_forward_on_the_local_port_is_refused(self):
        screen, app = make_app()
        process = MagicMock()
        process.poll.return_value = None
        app.forwards["43389"] = Forward(make_instances(1)[0], "3389", "43389", process)

        self.assertIsNone(self.choose([10, 10, 27, -1], app))
        drawn = [call.args[2] for call in screen.addnstr.call_args_list]
        self.assertTrue(any("localhost:43389 is already forwarded" in text for text in drawn))

    def test_ctrl_c_cancels(self):
        screen, app = make_app()
        screen.getch.side_effect = KeyboardInterrupt

        self.assertIsNone(app.choose_ports(make_instances(1)[0]))
        self.assertEqual(screen.timeout.call_args_list[-1], unittest.mock.call(200))

    def test_the_dialog_names_the_instance(self):
        screen, app = make_app()
        self.choose([27, -1], app)

        drawn = [call.args[2] for call in screen.addnstr.call_args_list]
        self.assertIn("Port forward to host000 (i-000)", drawn)

    @patch("ssmer.subprocess.Popen")
    def test_a_cancelled_dialog_starts_no_session(self, popen):
        screen, app = make_app()
        app.instances = make_instances(1)
        app.choose_ports = MagicMock(return_value=None)

        app.start_forward(app.instances[0])

        popen.assert_not_called()
        self.assertEqual(app.message, "Forward cancelled.")


class SsmReadinessTests(unittest.TestCase):
    @patch("ssmer.subprocess.run")
    def test_an_ssm_lookup_failure_is_reported_rather_than_shown_as_not_managed(self, run):
        run.side_effect = [
            MagicMock(returncode=0, stdout='{"Reservations":[{"Instances":[{"InstanceId":"i-123","State":{"Name":"running"}}]}]}'),
            MagicMock(returncode=255, stdout="", stderr="AccessDeniedException: not authorized"),
        ]
        warnings = []

        instances = get_instances(None, "eu-west-1", warnings.append)

        self.assertEqual(instances[0].ssm_status, "Not managed")
        self.assertEqual(len(warnings), 1)
        self.assertIn("AccessDeniedException", warnings[0])

    @patch("ssmer.local_port_in_use", new=MagicMock(return_value=False))
    @patch("ssmer.subprocess.Popen")
    def test_forward_flags_an_instance_that_is_not_reporting_to_ssm(self, popen):
        screen, app = make_app()
        app.instances = [Instance("i-123", "windows", "running", "t3.large", "10.0.0.10", "ConnectionLost")]
        app.choose_ports = MagicMock(return_value=("3389", "13389"))
        process = MagicMock()
        process.poll.return_value = None
        process.stdout = None
        popen.return_value = process

        app.start_forward(app.instances[0])

        self.assertIn("ConnectionLost", app.message)

    @patch("ssmer.local_port_in_use", new=MagicMock(return_value=False))
    @patch("ssmer.subprocess.Popen")
    def test_an_online_instance_gets_no_caveat(self, popen):
        screen, app = make_app()
        app.instances = [Instance("i-123", "windows", "running", "t3.large", "10.0.0.10", "Online")]
        app.choose_ports = MagicMock(return_value=("3389", "13389"))
        process = MagicMock()
        process.poll.return_value = None
        process.stdout = None
        popen.return_value = process

        app.start_forward(app.instances[0])

        self.assertEqual(app.message, "Connecting to windows: localhost:13389 → 3389…")


class InstanceFilterTests(unittest.TestCase):
    @patch("ssmer.subprocess.run")
    def test_requests_every_non_terminated_state(self, run):
        run.return_value = MagicMock(returncode=0, stdout='{"Reservations":[]}')

        get_instances(None, "eu-west-1")

        command = run.call_args_list[0].args[0]
        self.assertEqual(
            command[command.index("--filters") + 1],
            "Name=instance-state-name,Values=pending,running,shutting-down,stopping,stopped",
        )
        self.assertNotIn("terminated", NON_TERMINATED_STATES)


class QuitDisconnectTests(unittest.TestCase):
    @patch("ssmer.os.killpg")
    def test_quit_can_stop_active_forwards_on_the_way_out(self, killpg):
        screen, app = make_app()
        screen.getch.return_value = ord("d")
        process = MagicMock(pid=4321)
        process.poll.return_value = None
        app.forwards["13389"] = Forward(make_instances(1)[0], "3389", "13389", process)

        self.assertTrue(app.confirm_quit())
        killpg.assert_called_once_with(4321, signal.SIGTERM)

    def test_d_does_not_quit_when_no_forwards_are_active(self):
        screen, app = make_app()
        screen.getch.side_effect = [ord("d"), 27, -1]  # d is ignored; Esc then cancels

        self.assertFalse(app.confirm_quit())


class EntryPointTests(unittest.TestCase):
    @patch("ssmer.App")
    @patch("ssmer.curses.wrapper")
    def test_an_empty_argv_is_not_replaced_by_sys_argv(self, wrapper, app_class):
        with patch.object(sys, "argv", ["prog", "--profile", "leaked-from-sys-argv"]):
            self.assertEqual(main([]), 0)

        wrapper.call_args.args[0](MagicMock())  # invoke the callback curses.wrapper got
        self.assertIsNone(app_class.call_args.args[1])

    @patch("ssmer.curses.wrapper", side_effect=KeyboardInterrupt)
    def test_ctrl_c_exits_without_a_traceback(self, _wrapper):
        self.assertEqual(main([]), 130)


class BackgroundLoadingTests(unittest.TestCase):
    @patch("ssmer.threading.Thread")
    def test_reload_does_not_block_the_main_thread(self, thread):
        screen, app = make_app()

        app.start_reload()

        self.assertTrue(app.loading)
        self.assertEqual(app.message, "Loading instances…")
        thread.assert_called_once()
        self.assertTrue(thread.call_args.kwargs["daemon"])
        self.assertEqual(thread.call_args.kwargs["target"], app.load_instances)

    @patch("ssmer.get_instances")
    def test_a_finished_load_replaces_the_list(self, get):
        screen, app = make_app()
        get.return_value = make_instances(3)
        app.load_generation = 1
        app.loading = True

        app.load_instances(1, None, "eu-west-1")
        app.drain_load_results()

        self.assertFalse(app.loading)
        self.assertEqual(len(app.instances), 3)
        self.assertIn("3 instance(s)", app.message)

    @patch("ssmer.threading.Thread")
    @patch("ssmer.get_instances")
    def test_a_superseded_load_is_discarded(self, get, _thread):
        screen, app = make_app()
        get.return_value = make_instances(3)
        app.instances = make_instances(1)
        app.load_generation = 1

        app.load_instances(1, None, "eu-west-1")  # in flight when the region changed
        app.start_reload()  # bumps the generation; the worker is stubbed out
        app.drain_load_results()

        self.assertTrue(app.loading)  # still waiting on the newer fetch
        self.assertEqual(len(app.instances), 1)

    @patch("ssmer.get_instances", side_effect=RuntimeError("AccessDenied"))
    def test_a_failed_load_reports_the_error(self, _get):
        screen, app = make_app()
        app.load_generation = 1
        app.loading = True

        app.load_instances(1, None, "eu-west-1")
        app.drain_load_results()

        self.assertFalse(app.loading)
        self.assertEqual(app.instances, [])
        self.assertIn("AccessDenied", app.message)

    @patch("ssmer.get_instances", side_effect=FileNotFoundError("aws"))
    def test_a_missing_aws_cli_is_reported_rather_than_crashing(self, _get):
        screen, app = make_app()
        app.load_generation = 1
        app.loading = True

        app.load_instances(1, None, "eu-west-1")  # must not raise
        app.drain_load_results()

        self.assertIn("Could not load instances", app.message)

    def test_warnings_from_the_worker_go_through_the_thread_safe_queue(self):
        screen, app = make_app()
        with patch("ssmer.get_instances") as get:
            get.return_value = []
            app.load_instances(1, "dev", "eu-west-1")
        self.assertEqual(get.call_args.args[2], app.output_queue.put)


class LoadingAnimationTests(unittest.TestCase):
    def test_spinner_advances_through_every_frame(self):
        screen, app = make_app()
        app.loading = True

        rendered = []
        for frame in range(len(LOADING_FRAMES) + 2):
            app.spinner_frame = frame
            rendered.append(app.status_line())

        self.assertEqual(len(set(rendered)), len(LOADING_FRAMES))
        self.assertTrue(all(line.endswith("Loading instances…") for line in rendered))
        self.assertEqual(rendered[0], rendered[len(LOADING_FRAMES)])  # wraps around

    def test_no_spinner_once_loading_has_finished(self):
        screen, app = make_app()
        app.message = "3 instance(s)."

        self.assertEqual(app.status_line(), "3 instance(s).")

    def test_spinner_is_drawn_on_the_message_row(self):
        screen, app = make_app()
        app.loading = True
        app.spinner_frame = 3

        app.draw()

        message_row = [call.args[2] for call in screen.addnstr.call_args_list if call.args[0] == 15]
        self.assertIn(f" {LOADING_FRAMES[3]} Loading instances… ", message_row)

    def test_the_frame_has_no_title_and_carries_the_message(self):
        screen, app = make_app()
        app.region = "eu-west-2"
        app.instances = make_instances(4)
        app.message = "4 instance(s)."

        app.draw()

        drawn = {call.args[:3] for call in screen.addnstr.call_args_list}
        self.assertIn((HEADER_ROWS, 0, "┌" + "─" * 117 + "┐"), drawn)
        self.assertIn((15, 0, "└" + "─" * 117 + "┘"), drawn)
        self.assertFalse(any("Instances" in text for _, _, text in drawn))
        self.assertIn((15, 1, " 4 instance(s). "), drawn)
        self.assertTrue(all((row, 0, "│") in drawn and (row, 118, "│") in drawn for row in range(HEADER_ROWS + 1, 15)))

    def test_empty_list_message_is_withheld_while_loading(self):
        screen, app = make_app()
        app.loading = True

        app.draw()

        drawn = [call.args[2] for call in screen.addnstr.call_args_list]
        self.assertNotIn("No non-terminated EC2 instances found.", drawn)

    def test_empty_list_message_appears_once_loading_finished(self):
        screen, app = make_app()
        app.message = "0 instance(s)."

        app.draw()

        drawn = [call.args[2] for call in screen.addnstr.call_args_list]
        self.assertIn("No non-terminated EC2 instances found.", drawn)

    def test_polling_is_faster_while_loading(self):
        screen, app = make_app()
        self.assertEqual(app.poll_interval(), 200)
        app.loading = True
        self.assertLess(app.poll_interval(), 200)


class ActionMenuTests(unittest.TestCase):
    def test_enter_offers_connect_and_port_forward(self):
        self.assertEqual([action for action, *_ in ACTIONS], [CONNECT, PORT_FORWARD])

    def test_connect_runs_a_shell_session(self):
        screen, app = make_app()
        app.instances = make_instances(1)
        app.choose_action = MagicMock(return_value=CONNECT)
        app.start_shell = MagicMock()
        app.start_forward = MagicMock()

        app.act_on_selected()

        app.start_shell.assert_called_once_with(app.instances[0])
        app.start_forward.assert_not_called()

    def test_port_forward_prompts_for_ports(self):
        screen, app = make_app()
        app.instances = make_instances(1)
        app.choose_action = MagicMock(return_value=PORT_FORWARD)
        app.start_shell = MagicMock()
        app.start_forward = MagicMock(return_value=True)
        app.offer_admin_password = MagicMock()

        app.act_on_selected()

        app.start_forward.assert_called_once_with(app.instances[0])
        app.start_shell.assert_not_called()
        app.offer_admin_password.assert_called_once_with(app.instances[0])

    def test_no_password_is_offered_when_the_forward_does_not_start(self):
        screen, app = make_app()
        app.instances = make_instances(1)
        app.choose_action = MagicMock(return_value=PORT_FORWARD)
        app.start_forward = MagicMock(return_value=False)
        app.offer_admin_password = MagicMock()

        app.act_on_selected()

        app.offer_admin_password.assert_not_called()

    def test_a_cancelled_menu_does_nothing(self):
        screen, app = make_app()
        app.instances = make_instances(1)
        app.choose_action = MagicMock(return_value=None)
        app.start_shell = MagicMock()
        app.start_forward = MagicMock()

        app.act_on_selected()

        app.start_shell.assert_not_called()
        app.start_forward.assert_not_called()

    def test_a_stopped_instance_gets_no_menu(self):
        screen, app = make_app()
        app.instances = [Instance("i-123", "windows", "stopped", "t3.large", "10.0.0.10")]
        app.choose_action = MagicMock()

        app.act_on_selected()

        app.choose_action.assert_not_called()
        self.assertIn("stopped", app.message)

    def test_enter_picks_the_highlighted_action(self):
        screen, app = make_app()
        screen.getch.side_effect = [10]

        self.assertEqual(app.choose_action(make_instances(1)[0]), CONNECT)

    def test_arrows_move_the_highlight(self):
        screen, app = make_app()
        screen.getch.side_effect = [curses.KEY_DOWN, curses.KEY_DOWN, 10]  # clamps at the last entry

        self.assertEqual(app.choose_action(make_instances(1)[0]), PORT_FORWARD)

    def test_hotkeys_choose_directly(self):
        for key, action in (("c", CONNECT), ("p", PORT_FORWARD)):
            screen, app = make_app()
            screen.getch.side_effect = [ord(key)]

            self.assertEqual(app.choose_action(make_instances(1)[0]), action, key)

    def test_escape_cancels_and_restores_polling(self):
        screen, app = make_app()
        screen.getch.side_effect = [27, -1]

        self.assertIsNone(app.choose_action(make_instances(1)[0]))
        self.assertEqual(screen.timeout.call_args_list[0], unittest.mock.call(-1))
        self.assertEqual(screen.timeout.call_args_list[-1], unittest.mock.call(200))

    def test_the_highlighted_action_is_drawn_as_a_selection_bar(self):
        screen, app = make_app()

        app.draw_action_menu(make_instances(1)[0], 1)

        drawn = {call.args[2].strip(): call.args[4] for call in screen.addnstr.call_args_list if call.args[2].strip()}
        forward_row = next(attr for text, attr in drawn.items() if "Port Forward" in text)
        connect_row = next(attr for text, attr in drawn.items() if "Connect" in text)
        self.assertFalse(forward_row & curses.A_REVERSE)
        self.assertTrue(connect_row & curses.A_REVERSE)
        self.assertIn("host000 (i-000)", drawn)


class ShellSessionTests(unittest.TestCase):
    def setUp(self):
        self.calls = MagicMock()  # records curses and process calls in order
        for name in ("def_prog_mode", "endwin", "reset_prog_mode", "flushinp"):
            patcher = patch(f"ssmer.curses.{name}", getattr(self.calls, name))
            patcher.start()
            self.addCleanup(patcher.stop)
        for target, kwargs in (("sys.stdout", {"new_callable": io.StringIO}), ("builtins.input", {})):
            patcher = patch(target, **kwargs)
            setattr(self, target.split(".")[1], patcher.start())
            self.addCleanup(patcher.stop)
        popen = patch("ssmer.subprocess.Popen", self.calls.Popen)
        popen.start()
        self.addCleanup(popen.stop)
        self.process = self.calls.Popen.return_value
        self.process.wait.return_value = 0
        self.screen, self.app = make_app()
        self.target = make_instances(1)[0]

    def test_starts_a_default_session_with_the_callers_profile_and_region(self):
        self.app.profile, self.app.region = "dev", "eu-west-1"

        self.app.start_shell(self.target)

        self.calls.Popen.assert_called_once_with(
            ["aws", "--profile", "dev", "--region", "eu-west-1", "ssm", "start-session", "--target", "i-000"]
        )

    def test_the_tui_is_suspended_for_exactly_the_length_of_the_session(self):
        self.app.start_shell(self.target)

        order = [name for name, *_ in self.calls.mock_calls if name in ("endwin", "Popen", "Popen().wait", "reset_prog_mode")]
        self.assertEqual(order, ["endwin", "Popen", "Popen().wait", "reset_prog_mode"])
        self.calls.flushinp.assert_called_once()
        self.screen.clear.assert_called_once()

    def test_terminal_signals_are_ignored_only_while_the_session_runs(self):
        before = {signum: signal.getsignal(signum) for signum in USER_SIGNALS}
        during = {}
        self.process.wait.side_effect = lambda: during.update({s: signal.getsignal(s) for s in USER_SIGNALS}) or 0

        self.app.start_shell(self.target)

        self.assertEqual(during, {signum: signal.SIG_IGN for signum in USER_SIGNALS})
        self.assertEqual({signum: signal.getsignal(signum) for signum in USER_SIGNALS}, before)

    def test_a_clean_exit_returns_straight_to_the_list(self):
        self.app.start_shell(self.target)

        self.input.assert_not_called()
        self.assertEqual(self.app.message, "Session with host000 closed.")
        self.assertIn("Session with i-000 ended (exit status 0).", self.app.output)

    def test_a_failed_session_pauses_so_its_error_stays_readable(self):
        self.process.wait.return_value = 255

        self.app.start_shell(self.target)

        self.input.assert_called_once()
        self.assertIn("exit status 255", self.app.message)
        self.assertIn("SSM status: Not managed", self.app.message)

    def test_ctrl_d_at_the_pause_still_returns_to_the_list(self):
        self.process.wait.return_value = 255
        self.input.side_effect = EOFError

        self.app.start_shell(self.target)

        self.calls.reset_prog_mode.assert_called_once()

    def test_a_missing_aws_cli_is_reported_and_the_tui_comes_back(self):
        self.calls.Popen.side_effect = FileNotFoundError("aws")

        self.app.start_shell(self.target)

        self.assertIn("Could not start AWS CLI", self.app.message)
        self.calls.reset_prog_mode.assert_called_once()
        self.input.assert_not_called()


TWELVE_OCLOCK = -math.pi / 2


class RadarFrameTests(unittest.TestCase):
    def test_frame_fills_the_requested_grid_with_braille(self):
        frame = radar_frame(20, 10, TWELVE_OCLOCK, [])

        self.assertEqual(len(frame), 10)
        for text, levels in frame:
            self.assertEqual((len(text), len(levels)), (20, 20))
            for char, level in zip(text, levels, strict=True):
                if char == " ":
                    self.assertEqual(level, -1)
                else:
                    self.assertTrue(0x2800 < ord(char) <= 0x28FF, char)
                    self.assertIn(level, range(4))

    def test_the_beam_is_brightest_where_it_points(self):
        frame = radar_frame(20, 10, TWELVE_OCLOCK, [])
        column = [levels[10] for _, levels in frame]

        self.assertEqual(column[1], 3)  # just inside the rim, straight up
        self.assertLess(max(column[6:]), 3)  # nothing lit below the centre

    def test_the_rings_stay_on_screen_when_the_beam_is_elsewhere(self):
        frame = radar_frame(20, 10, 0.0, [])

        self.assertEqual(frame[0][1][10], 0)  # the top of the outer ring, dimmest level

    def test_a_blip_flares_as_the_beam_crosses_it_and_fades_afterwards(self):
        blip = (0.0, 0.6)  # three o'clock
        fresh = radar_frame(20, 10, 0.05, [blip])
        stale = radar_frame(20, 10, 0.05 + 1.5 * math.pi, [blip])
        empty = radar_frame(20, 10, 0.05 + 1.5 * math.pi, [])

        row, col = 5, 16  # where the blip sits, clear of the beam in both frames
        self.assertEqual(fresh[row][1][col], 3)
        self.assertEqual(stale[row][1][col], empty[row][1][col])

    def test_blips_are_fixed_per_region(self):
        self.assertEqual(radar_blips("eu-west-1"), radar_blips("eu-west-1"))
        self.assertNotEqual(radar_blips("eu-west-1"), radar_blips("ap-northeast-3"))


class RadarDrawTests(unittest.TestCase):
    def drawn(self, screen):
        return {(call.args[0], call.args[2]) for call in screen.addnstr.call_args_list}

    def radar_rows(self, screen, app):
        """Rows holding braille, leaving out the spinner on the status line."""
        return {
            row
            for row, text in self.drawn(screen)
            if text.strip() != app.status_line() and any(0x2800 < ord(c) <= 0x28FF for c in text)
        }

    def test_radar_fills_the_empty_list_while_loading(self):
        screen, app = make_app()
        app.region = "ap-northeast-3"
        app.loading = True

        app.draw()

        rows = self.radar_rows(screen, app)
        self.assertTrue(rows)
        self.assertTrue(all(3 <= row < 15 for row in rows))  # inside the list area
        captions = [text for _, text in self.drawn(screen) if text.startswith("Scanning")]
        self.assertEqual(len(captions), 1)
        self.assertIn("ap-northeast-3", captions[0])

    def test_a_refresh_keeps_showing_the_current_list(self):
        screen, app = make_app()
        app.instances = make_instances(2)
        app.loading = True

        app.draw()

        self.assertIn((LIST_TOP, make_instances(1)[0].label), self.drawn(screen))
        self.assertFalse(any(text.startswith("Scanning") for _, text in self.drawn(screen)))

    def test_a_short_terminal_gets_the_caption_without_the_radar(self):
        screen, app = make_app(rows=10, columns=40)
        app.loading = True

        app.draw()

        self.assertTrue(any(text.startswith("Scanning") for _, text in self.drawn(screen)))
        self.assertEqual(self.radar_rows(screen, app), set())

    @patch("ssmer.threading.Thread")
    def test_switching_region_clears_the_old_regions_rows(self, _thread):
        screen, app = make_app()
        app.instances = make_instances(3)
        app.selected = 2
        app.select_region = MagicMock(return_value=True)

        app.switch_region()

        self.assertEqual(app.instances, [])
        self.assertEqual(app.selected, 0)
        self.assertTrue(app.loading)

    def test_cancelling_the_region_picker_keeps_the_list(self):
        screen, app = make_app()
        app.instances = make_instances(3)
        app.select_region = MagicMock(return_value=False)

        app.switch_region()

        self.assertEqual(len(app.instances), 3)


class UnmanagedRowColourTests(unittest.TestCase):
    def row_attr(self, instance, **app_attrs):
        screen = MagicMock()
        screen.getmaxyx.return_value = (24, 120)
        app = App(screen, None, None)
        for name, value in app_attrs.items():
            setattr(app, name, value)
        app.instances = [instance]
        app.draw()
        return next(call for call in screen.addnstr.call_args_list if call.args[:2] == (LIST_TOP, 2)).args[4]

    def test_not_managed_row_is_greyed(self):
        instance = Instance("i-123", "windows", "running", "t3.large", "10.0.0.10", NOT_MANAGED)

        self.assertTrue(self.row_attr(instance, unmanaged_attr=64) & 64)

    def test_managed_row_is_not_greyed(self):
        instance = Instance("i-123", "windows", "running", "t3.large", "10.0.0.10", "Online")

        self.assertFalse(self.row_attr(instance, unmanaged_attr=64) & 64)

    def test_other_ssm_states_are_not_greyed(self):
        for status in ("Online", "ConnectionLost", "Inactive"):
            instance = Instance("i-123", "windows", "running", "t3.large", "10.0.0.10", status)

            self.assertFalse(self.row_attr(instance, unmanaged_attr=64) & 64, status)

    def test_grey_survives_alongside_the_selection_highlight(self):
        instance = Instance("i-123", "windows", "running", "t3.large", "10.0.0.10", NOT_MANAGED)

        attr = self.row_attr(instance, unmanaged_attr=64)

        self.assertTrue(attr & 64)
        self.assertTrue(attr & curses.A_REVERSE)

    def test_a_stopped_unmanaged_row_keeps_both_hints(self):
        instance = Instance("i-123", "windows", "stopped", "t3.large", "10.0.0.10", NOT_MANAGED)

        attr = self.row_attr(instance, unmanaged_attr=64)

        self.assertTrue(attr & 64)
        self.assertTrue(attr & curses.A_DIM)

    def test_default_grey_is_dim_before_colours_are_configured(self):
        screen, app = make_app()

        self.assertEqual(app.unmanaged_attr, curses.A_DIM)

    @patch("ssmer.curses.color_pair", return_value=4096)
    @patch("ssmer.curses.init_pair")
    @patch("ssmer.curses.use_default_colors")
    @patch("ssmer.curses.start_color")
    @patch("ssmer.curses.has_colors", return_value=True)
    def test_a_colour_terminal_gets_a_real_grey(self, _has, _start, _defaults, init_pair, _pair):
        screen, app = make_app()
        with patch("ssmer.curses.COLORS", 256, create=True):
            app.configure_colors()

        self.assertIn(unittest.mock.call(3, GREY_COLOR, -1), init_pair.call_args_list)
        self.assertEqual(app.unmanaged_attr, 4096)
        for pair, color in enumerate(RADAR_COLORS, start=4):
            self.assertIn(unittest.mock.call(pair, color, -1), init_pair.call_args_list)

    @patch("ssmer.curses.color_pair", return_value=4096)
    @patch("ssmer.curses.init_pair")
    @patch("ssmer.curses.use_default_colors")
    @patch("ssmer.curses.start_color")
    @patch("ssmer.curses.has_colors", return_value=True)
    def test_an_eight_colour_terminal_falls_back_to_dim(self, _has, _start, _defaults, init_pair, _pair):
        screen, app = make_app()
        with patch("ssmer.curses.COLORS", 8, create=True):
            app.configure_colors()

        self.assertNotIn(unittest.mock.call(3, GREY_COLOR, -1), init_pair.call_args_list)
        self.assertEqual(app.unmanaged_attr, curses.A_DIM)


if __name__ == "__main__":
    unittest.main()


class AdminPasswordTests(unittest.TestCase):
    def make_keys(self, *names):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        for name in names:
            Path(directory.name, name).write_text("key")
        return Path(directory.name)

    def test_a_directory_lists_subdirectories_and_files_apart_without_hidden_entries(self):
        keys = self.make_keys("b.pem", "A.pem", ".hidden")
        (keys / "Zeta").mkdir()
        (keys / "alpha").mkdir()
        (keys / ".git").mkdir()

        subdirectories, files = list_key_directory(keys)

        self.assertEqual([entry.name for entry in subdirectories], ["alpha", "Zeta"])
        self.assertEqual([entry.name for entry in files], ["A.pem", "b.pem"])

    def test_key_files_are_found_at_any_depth(self):
        keys = self.make_keys("top.pem")
        (keys / "Customer" / "emea").mkdir(parents=True)
        (keys / "Customer" / "emea" / "deep.pem").write_text("key")
        (keys / ".hidden").mkdir()
        (keys / ".hidden" / "secret.pem").write_text("key")

        self.assertEqual([key.name for key in find_key_files(keys)], ["deep.pem", "top.pem"])

    def test_the_placeholder_note_is_not_offered_as_a_key(self):
        keys = self.make_keys(KEYS_PLACEHOLDER, "real.pem")

        self.assertEqual([key.name for key in find_key_files(keys)], ["real.pem"])
        self.assertEqual(list_key_directory(keys)[1], [keys / "real.pem"])

    def test_a_keys_directory_holding_only_the_placeholder_has_no_keys(self):
        screen, app = make_app()
        app.keys_dir = self.make_keys(KEYS_PLACEHOLDER)
        app.choose_key = MagicMock()

        app.offer_admin_password(make_instances(1)[0])

        app.choose_key.assert_not_called()
        self.assertIn("No EC2 key files", app.message)

    def test_a_missing_keys_directory_has_no_keys(self):
        self.assertEqual(find_key_files(Path("/nonexistent/keys")), [])
        self.assertEqual(list_key_directory(Path("/nonexistent/keys")), ([], []))

    def test_only_empty_subdirectories_still_counts_as_no_keys(self):
        screen, app = make_app()
        app.keys_dir = self.make_keys()
        (app.keys_dir / "Customer").mkdir()
        app.choose_key = MagicMock()

        app.offer_admin_password(make_instances(1)[0])

        app.choose_key.assert_not_called()
        self.assertIn("No EC2 key files", app.message)

    def test_the_browser_opens_on_the_launch_key_wherever_it_is(self):
        screen, app = make_app()
        app.keys_dir = self.make_keys("other.pem")
        (app.keys_dir / "Customer").mkdir()
        (app.keys_dir / "Customer" / "prod.pem").write_text("key")
        app.choose_key = MagicMock(return_value=None)
        target = Instance("i-1", "win", "running", "t3.large", "10.0.0.1", "Online", "prod")

        app.offer_admin_password(target)

        app.choose_key.assert_called_once_with(target, app.keys_dir, app.keys_dir / "Customer" / "prod.pem")

    def test_no_keys_is_an_error_but_the_forward_carries_on(self):
        screen, app = make_app()
        app.keys_dir = self.make_keys()
        app.message = "Connecting to host000: localhost:43389 → 3389…"
        app.choose_key = MagicMock()

        app.offer_admin_password(make_instances(1)[0])

        app.choose_key.assert_not_called()
        self.assertTrue(app.message.startswith("Connecting to host000"))
        self.assertIn("No EC2 key files", app.message)
        self.assertTrue(any(line.startswith("Error: No EC2 key files") for line in app.output))

    @patch("ssmer.threading.Thread")
    def test_the_chosen_key_is_fetched_off_the_main_thread(self, thread):
        screen, app = make_app()
        app.keys_dir = self.make_keys("a.pem", "b.pem")
        target = make_instances(1)[0]
        app.choose_key = MagicMock(return_value=app.keys_dir / "b.pem")

        app.offer_admin_password(target)

        self.assertEqual(thread.call_args.kwargs["args"][:2], (target, app.keys_dir / "b.pem"))
        thread.return_value.start.assert_called_once()

    @patch("ssmer.threading.Thread")
    def test_skipping_the_picker_fetches_nothing(self, thread):
        screen, app = make_app()
        app.keys_dir = self.make_keys("a.pem")
        app.choose_key = MagicMock(return_value=None)

        app.offer_admin_password(make_instances(1)[0])

        thread.assert_not_called()

    def make_tree(self):
        """keys/ holding a.pem, and Customer/ holding emea/ and c.pem, with emea/ holding e.pem."""
        keys = self.make_keys("a.pem")
        (keys / "Customer" / "emea").mkdir(parents=True)
        (keys / "Customer" / "c.pem").write_text("key")
        (keys / "Customer" / "emea" / "e.pem").write_text("key")
        return keys

    def test_directories_come_first_and_enter_opens_them(self):
        screen, app = make_app()
        keys = self.make_tree()
        # Customer/ is first; inside, ../ then emea/ then c.pem.
        screen.getch.side_effect = [10, curses.KEY_DOWN, 10, curses.KEY_DOWN, 10]

        self.assertEqual(app.choose_key(make_instances(1)[0], keys), keys / "Customer" / "emea" / "e.pem")

    def test_a_file_is_picked_with_enter(self):
        screen, app = make_app()
        keys = self.make_tree()
        screen.getch.side_effect = [curses.KEY_DOWN, 10]

        self.assertEqual(app.choose_key(make_instances(1)[0], keys), keys / "a.pem")

    def test_going_up_highlights_the_directory_just_left(self):
        screen, app = make_app()
        keys = self.make_tree()
        # Into Customer/, into emea/, back up with ←, then Enter goes back into emea/.
        screen.getch.side_effect = [10, curses.KEY_DOWN, 10, curses.KEY_LEFT, 10, curses.KEY_DOWN, 10]

        self.assertEqual(app.choose_key(make_instances(1)[0], keys), keys / "Customer" / "emea" / "e.pem")

    def test_the_parent_entry_goes_up(self):
        screen, app = make_app()
        keys = self.make_tree()
        # Into Customer/, Enter on ../, then Customer/ is highlighted; down to a.pem.
        screen.getch.side_effect = [10, 10, curses.KEY_DOWN, 10]

        self.assertEqual(app.choose_key(make_instances(1)[0], keys), keys / "a.pem")

    def test_the_browser_never_goes_above_the_keys_directory(self):
        screen, app = make_app()
        keys = self.make_tree()
        screen.getch.side_effect = [curses.KEY_LEFT, 127, curses.KEY_DOWN, 10]

        self.assertEqual(app.choose_key(make_instances(1)[0], keys), keys / "a.pem")

    def test_right_opens_a_directory_but_does_not_pick_a_file(self):
        screen, app = make_app()
        keys = self.make_tree()
        screen.getch.side_effect = [curses.KEY_RIGHT, curses.KEY_DOWN, curses.KEY_DOWN, curses.KEY_RIGHT, 10]

        self.assertEqual(app.choose_key(make_instances(1)[0], keys), keys / "Customer" / "c.pem")

    def test_the_browser_starts_on_the_launch_key(self):
        screen, app = make_app()
        keys = self.make_tree()
        screen.getch.side_effect = [10]

        self.assertEqual(
            app.choose_key(make_instances(1)[0], keys, keys / "Customer" / "c.pem"), keys / "Customer" / "c.pem"
        )

    def test_escape_skips_and_restores_polling(self):
        screen, app = make_app()
        screen.getch.side_effect = [10, 27, -1]

        self.assertIsNone(app.choose_key(make_instances(1)[0], self.make_tree()))
        self.assertEqual(screen.timeout.call_args_list[-1], unittest.mock.call(200))

    def test_an_empty_directory_can_be_left(self):
        screen, app = make_app()
        keys = self.make_keys("a.pem")
        (keys / "Empty").mkdir()
        screen.getch.side_effect = [10, 10, curses.KEY_DOWN, 10]  # into Empty/, ../, a.pem

        self.assertEqual(app.choose_key(make_instances(1)[0], keys), keys / "a.pem")

    def test_the_picker_shows_where_it_is_and_marks_directories(self):
        screen, app = make_app()
        keys = self.make_tree()

        app.draw_key_picker(make_instances(1)[0], keys, keys / "Customer", [keys, keys / "Customer" / "emea", keys / "Customer" / "c.pem"], 1)

        drawn = {call.args[2].strip(): call.args[4] for call in screen.addnstr.call_args_list if call.args[2].strip()}
        self.assertIn(f"{keys.name}/Customer/", drawn)
        self.assertIn("../", drawn)
        self.assertIn("c.pem", drawn)
        self.assertFalse(drawn["emea/"] & curses.A_REVERSE)  # the selection bar

    def test_a_long_directory_scrolls_and_shows_the_position(self):
        screen, app = make_app()
        keys = self.make_keys(*(f"k{n:02d}.pem" for n in range(30)))
        entries = list_key_directory(keys)[1]

        app.draw_key_picker(make_instances(1)[0], keys, keys, entries, 25)

        texts = [call.args[2].strip() for call in screen.addnstr.call_args_list]
        self.assertIn(f"{keys.name}/  [26/30]", texts)
        self.assertIn("k25.pem", texts)
        self.assertNotIn("k00.pem", texts)

    @patch("ssmer.subprocess.run")
    def test_password_is_decrypted_by_the_aws_cli(self, run):
        run.return_value = MagicMock(returncode=0, stdout='{"InstanceId": "i-1", "PasswordData": "s3cret"}', stderr="")

        self.assertEqual(get_admin_password("prod", "eu-west-1", "i-1", Path("keys/a.pem")), "s3cret")
        self.assertEqual(
            run.call_args.args[0],
            ["aws", "--profile", "prod", "--region", "eu-west-1", "ec2", "get-password-data",
             "--instance-id", "i-1", "--priv-launch-key", "keys/a.pem", "--output", "json"],
        )

    @patch("ssmer.subprocess.run")
    def test_an_empty_password_is_an_error(self, run):
        run.return_value = MagicMock(returncode=0, stdout='{"PasswordData": ""}', stderr="")

        with self.assertRaisesRegex(RuntimeError, "no password available"):
            get_admin_password(None, None, "i-1", Path("a.pem"))

    @patch("ssmer.subprocess.run")
    def test_a_cli_failure_carries_its_message(self, run):
        run.return_value = MagicMock(returncode=255, stdout="", stderr="Unable to decrypt password data")

        with self.assertRaisesRegex(RuntimeError, "Unable to decrypt"):
            get_admin_password(None, None, "i-1", Path("a.pem"))

    @patch("ssmer.copy_to_clipboard", return_value="wl-copy")
    @patch("ssmer.get_admin_password", return_value="s3cret")
    def test_a_fetched_password_is_copied_and_never_shown(self, _get, copy):
        screen, app = make_app()

        app.fetch_admin_password(make_instances(1)[0], Path("a.pem"), None, None)
        app.drain_output()

        copy.assert_called_once_with("s3cret")
        self.assertIn("copied to the clipboard", app.message)
        self.assertFalse(any("s3cret" in line for line in [app.message, *app.output]))

    @patch("ssmer.copy_to_clipboard", return_value=None)
    @patch("ssmer.get_admin_password", return_value="s3cret")
    def test_without_a_clipboard_the_password_goes_on_the_status_line_only(self, _get, _copy):
        screen, app = make_app()

        app.fetch_admin_password(make_instances(1)[0], Path("a.pem"), None, None)
        app.drain_output()

        self.assertIn("s3cret", app.message)
        self.assertFalse(any("s3cret" in line for line in app.output))

    @patch("ssmer.get_admin_password", side_effect=RuntimeError("Unable to decrypt password data"))
    def test_a_failed_fetch_is_reported(self, _get):
        screen, app = make_app()

        app.fetch_admin_password(make_instances(1)[0], Path("a.pem"), None, None)
        app.drain_output()

        self.assertIn("Unable to decrypt", app.message)

    @patch("ssmer.subprocess.run")
    @patch("ssmer.shutil.which", side_effect=lambda name: f"/usr/bin/{name}" if name == "xclip" else None)
    def test_clipboard_uses_the_first_available_tool(self, _which, run):
        run.return_value = MagicMock(returncode=0)
        with patch.dict(os.environ, {"DISPLAY": ":0"}, clear=True):
            self.assertEqual(copy_to_clipboard("s3cret"), "xclip")
        self.assertEqual(run.call_args.args[0], ("xclip", "-selection", "clipboard"))
        self.assertEqual(run.call_args.kwargs["input"], "s3cret")

    @patch("ssmer.shutil.which", return_value=None)
    def test_clipboard_reports_when_nothing_is_available(self, _which):
        self.assertIsNone(copy_to_clipboard("s3cret"))


class ArgumentTests(unittest.TestCase):
    def test_the_keys_directory_defaults_to_keys_beside_the_script(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(parse_args([]).keys_dir, Path(__file__).resolve().parent.parent / "keys")

    def test_the_environment_and_the_flag_override_the_keys_directory(self):
        with patch.dict(os.environ, {"SSMER_KEYS_DIR": "/env/keys"}):
            self.assertEqual(parse_args([]).keys_dir, Path("/env/keys"))
            self.assertEqual(parse_args(["--keys-dir", "/flag/keys"]).keys_dir, Path("/flag/keys"))

    def test_version_prints_and_exits(self):
        with patch("sys.stdout", new=io.StringIO()) as stdout, self.assertRaises(SystemExit) as exit:
            parse_args(["--version"])
        self.assertEqual(exit.exception.code, 0)
        self.assertRegex(stdout.getvalue(), r"\d+\.\d+\.\d+")
