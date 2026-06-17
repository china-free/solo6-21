import click
import sys
from datetime import datetime, timedelta
from typing import List, Optional
from colorama import init, Fore, Style

from ..config import AppConfig
from ..sources import create_source, LogSource, LogEntry
from ..aggregator import LogAggregator
from ..filters import FilterEngine
from ..alerts import AlertEngine, Alert
from ..session import SessionManager, AnalysisSession

init()

LEVEL_COLORS = {
    "DEBUG": Fore.CYAN,
    "INFO": Fore.GREEN,
    "WARN": Fore.YELLOW,
    "ERROR": Fore.RED,
    "FATAL": Fore.MAGENTA,
}

SEVERITY_COLORS = {
    "critical": Fore.RED,
    "error": Fore.RED,
    "warning": Fore.YELLOW,
    "info": Fore.BLUE,
}


def _print_entry(entry: LogEntry, show_source: bool = True, no_color: bool = False) -> None:
    ts = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    level = entry.level.upper()
    
    if no_color:
        if show_source:
            click.echo(f"[{ts}] [{level}] [{entry.source}] {entry.raw_message}")
        else:
            click.echo(f"[{ts}] [{level}] {entry.raw_message}")
    else:
        color = LEVEL_COLORS.get(level, Fore.WHITE)
        if show_source:
            click.echo(
                f"{Fore.LIGHTBLACK_EX}[{ts}]{Style.RESET_ALL} "
                f"{color}[{level}]{Style.RESET_ALL} "
                f"{Fore.BLUE}[{entry.source}]{Style.RESET_ALL} "
                f"{entry.raw_message}"
            )
        else:
            click.echo(
                f"{Fore.LIGHTBLACK_EX}[{ts}]{Style.RESET_ALL} "
                f"{color}[{level}]{Style.RESET_ALL} "
                f"{entry.raw_message}"
            )


def _print_alert(alert: Alert, no_color: bool = False) -> None:
    if no_color:
        click.echo(f"[{alert.severity.upper()}] ALERT: {alert.rule_name}")
        click.echo(f"  Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        click.echo(f"  Count: {alert.count}")
        click.echo(f"  Message: {alert.message}")
    else:
        color = SEVERITY_COLORS.get(alert.severity.lower(), Fore.WHITE)
        click.echo(
            f"{color}[{alert.severity.upper()}] ALERT: {alert.rule_name}{Style.RESET_ALL}"
        )
        click.echo(
            f"  {Fore.LIGHTBLACK_EX}Time:{Style.RESET_ALL} "
            f"{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        click.echo(
            f"  {Fore.LIGHTBLACK_EX}Count:{Style.RESET_ALL} {alert.count}"
        )
        click.echo(
            f"  {Fore.LIGHTBLACK_EX}Message:{Style.RESET_ALL} {alert.message}"
        )


def _parse_time(time_str: str) -> Optional[datetime]:
    if not time_str:
        return None
    
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
        "%H:%M:%S",
    ]
    
    for fmt in formats:
        try:
            parsed = datetime.strptime(time_str, fmt)
            if fmt == "%H:%M:%S":
                now = datetime.now()
                parsed = parsed.replace(year=now.year, month=now.month, day=now.day)
            return parsed
        except ValueError:
            continue
    
    if time_str.endswith("h"):
        hours = int(time_str[:-1])
        return datetime.now() - timedelta(hours=hours)
    elif time_str.endswith("d"):
        days = int(time_str[:-1])
        return datetime.now() - timedelta(days=days)
    elif time_str.endswith("m"):
        minutes = int(time_str[:-1])
        return datetime.now() - timedelta(minutes=minutes)
    
    raise click.BadParameter(f"Invalid time format: {time_str}")


def _load_config(config_path: str) -> AppConfig:
    try:
        return AppConfig.load_from_file(config_path)
    except Exception as e:
        click.echo(f"{Fore.RED}Error loading config: {e}{Style.RESET_ALL}", err=True)
        sys.exit(1)


def _create_sources_from_config(config: AppConfig, source_names: Optional[List[str]] = None) -> List[LogSource]:
    sources = []
    for src_config in config.sources:
        if not src_config.enabled:
            continue
        if source_names and src_config.name not in source_names:
            continue
        
        try:
            source = create_source(src_config.type, src_config.name, src_config.config)
            sources.append(source)
        except Exception as e:
            click.echo(f"{Fore.YELLOW}Warning: Failed to create source '{src_config.name}': {e}{Style.RESET_ALL}", err=True)
    
    return sources


@click.group()
@click.version_option()
@click.option("--config", "-c", default="logalyzer.yaml", help="Configuration file path")
@click.option("--no-color", is_flag=True, help="Disable colored output")
@click.pass_context
def cli(ctx, config: str, no_color: bool):
    """Multi-source log aggregation and analysis tool."""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config
    ctx.obj["no_color"] = no_color
    ctx.obj["config"] = _load_config(config)


@cli.group()
def collect():
    """Collect logs from multiple sources."""
    pass


@collect.command("run")
@click.option("--source", "-s", multiple=True, help="Collect from specific source(s) only")
@click.option("--start-time", "-t", help="Start time (format: YYYY-MM-DD HH:MM:SS or relative: 24h, 7d)")
@click.option("--end-time", "-e", help="End time (format: YYYY-MM-DD HH:MM:SS)")
@click.option("--follow", "-f", is_flag=True, help="Follow log output in real-time")
@click.option("--output", "-o", help="Output file path to save collected logs")
@click.option("--save-session", help="Save collected logs to a session with given name")
@click.option("--no-filter", is_flag=True, help="Do not apply filters from config")
@click.option("--no-alert", is_flag=True, help="Do not apply alerts from config")
@click.pass_context
def collect_run(
    ctx,
    source: List[str],
    start_time: str,
    end_time: str,
    follow: bool,
    output: str,
    save_session: str,
    no_filter: bool,
    no_alert: bool,
):
    """Collect and display logs from configured sources."""
    config = ctx.obj["config"]
    no_color = ctx.obj["no_color"]
    
    try:
        start_dt = _parse_time(start_time) if start_time else None
        end_dt = _parse_time(end_time) if end_time else None
    except click.BadParameter as e:
        click.echo(f"{Fore.RED}{e}{Style.RESET_ALL}", err=True)
        sys.exit(1)
    
    sources = _create_sources_from_config(config, list(source) if source else None)
    if not sources:
        click.echo(f"{Fore.RED}No valid sources found{Style.RESET_ALL}", err=True)
        sys.exit(1)
    
    click.echo(f"{Fore.BLUE}Collecting logs from {len(sources)} source(s)...{Style.RESET_ALL}")
    for s in sources:
        click.echo(f"  - {s.name} ({s.config.get('path', s.config.get('host', ''))})")
    
    aggregator = LogAggregator(sources)
    
    filter_engine = FilterEngine()
    if not no_filter and source:
        filter_engine.add_source_filter(list(source))
    
    alert_engine = AlertEngine()
    if not no_alert:
        alert_engine.add_rules_from_config(config.alert_rules)
        alert_engine.add_alert_callback(lambda a: _print_alert(a, no_color))
    
    collected_logs: List[LogEntry] = []
    latest_cursors: Dict[str, Dict[str, Any]] = {}
    
    try:
        source_cursors: Dict[str, Dict[str, Any]] = {}
        if start_dt:
            for s in sources:
                source_cursors[s.name] = {"last_timestamp": start_dt.isoformat()}
        log_stream = aggregator.aggregate_incremental(source_cursors, end_dt, follow)
        def _wrap():
            nonlocal latest_cursors
            for entry, cursor_map in log_stream:
                for src, cur in cursor_map.items():
                    latest_cursors[src] = cur
                yield entry
        stream = _wrap()
        if not no_filter:
            stream = filter_engine.filter(stream)
        if not no_alert:
            stream = alert_engine.process_entries(stream)
        
        for entry in stream:
            collected_logs.append(entry)
            _print_entry(entry, show_source=True, no_color=no_color)
            
            if output:
                with open(output, "a", encoding="utf-8") as f:
                    f.write(str(entry) + "\n")
    except KeyboardInterrupt:
        click.echo(f"\n{Fore.YELLOW}Interrupted by user{Style.RESET_ALL}")
    finally:
        click.echo(f"\n{Fore.GREEN}Collected {len(collected_logs)} log entries{Style.RESET_ALL}")
        
        alerts = alert_engine.check_alerts()
        if alerts:
            click.echo(f"{Fore.YELLOW}Triggered {len(alerts)} alert(s){Style.RESET_ALL}")
        
        if save_session:
            from ..session.manager import SourceCursor
            session_manager = SessionManager(config.session_dir)
            session = session_manager.create_session(
                name=save_session,
                description=f"Collected on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                log_entries=collected_logs,
                filter_engine=filter_engine,
                alert_engine=alert_engine,
                source_names=[s.name for s in sources],
                start_time=start_dt,
                end_time=end_dt,
            )
            for src_name, cur_dict in latest_cursors.items():
                session.source_cursors[src_name] = SourceCursor.from_dict(cur_dict)
            session_path = session_manager.save_session(session)
            click.echo(f"{Fore.GREEN}Session saved: {session.id} -> {session_path}{Style.RESET_ALL}")
            click.echo(f"{Fore.BLUE}  Source cursors saved for resume.{Style.RESET_ALL}")


@collect.command("sources")
@click.pass_context
def collect_sources(ctx):
    """List all configured log sources."""
    config = ctx.obj["config"]
    no_color = ctx.obj["no_color"]
    
    if not config.sources:
        click.echo("No sources configured")
        return
    
    click.echo(f"Configured {len(config.sources)} source(s):")
    for src in config.sources:
        status = f"{Fore.GREEN}enabled{Style.RESET_ALL}" if src.enabled else f"{Fore.RED}disabled{Style.RESET_ALL}"
        if no_color:
            status = "enabled" if src.enabled else "disabled"
        
        click.echo(f"  - {src.name} ({src.type}) [{status}]")
        if src.type == "local":
            click.echo(f"      Path: {src.config.get('path', 'N/A')}")
        elif src.type == "ssh":
            click.echo(f"      Host: {src.config.get('host', 'N/A')}:{src.config.get('port', 22)}")
            click.echo(f"      User: {src.config.get('username', 'N/A')}")
            click.echo(f"      Path: {src.config.get('log_path', 'N/A')}")
        elif src.type == "cloud":
            click.echo(f"      Provider: {src.config.get('provider', 's3')}")
            click.echo(f"      Bucket: {src.config.get('bucket', 'N/A')}")
            click.echo(f"      Prefix: {src.config.get('prefix', '')}")


@collect.command("resume")
@click.argument("session_id")
@click.option("--source", "-s", multiple=True, help="Resume only specific source(s)")
@click.option("--end-time", "-e", help="End time for incremental collection")
@click.option("--follow", "-f", is_flag=True, help="Follow log output in real-time after resume")
@click.option("--output", "-o", help="Output file path to append new logs")
@click.option("--no-filter", is_flag=True, help="Do not apply saved filters")
@click.option("--no-alert", is_flag=True, help="Do not apply saved alert engine")
@click.option("--no-save", is_flag=True, help="Do not update the session (dry run)")
@click.pass_context
def collect_resume(ctx, **kwargs):
    """Alias for 'session resume' - incrementally collect new logs into a saved session."""
    ctx.invoke(session_resume, **kwargs)


@cli.group()
def filter():
    """Filter collected logs."""
    pass


@filter.command("run")
@click.option("--session", "session_id", help="Session ID to filter logs from")
@click.option("--input", "-i", "input_file", help="Input log file (alternative to session)")
@click.option("--keyword", "-k", multiple=True, help="Filter by keyword (case-insensitive)")
@click.option("--regex", "-r", multiple=True, help="Filter by regular expression")
@click.option("--level", "-l", multiple=True, help="Filter by log level (DEBUG, INFO, WARN, ERROR, FATAL)")
@click.option("--source", "-s", multiple=True, help="Filter by source name")
@click.option("--start-time", "-t", help="Start time filter")
@click.option("--end-time", "-e", help="End time filter")
@click.option("--case-sensitive", is_flag=True, help="Case-sensitive keyword matching")
@click.option("--output", "-o", help="Output file path")
@click.option("--count", "-n", type=int, help="Only show first N entries")
@click.option("--save-session", help="Save filtered results to a new session")
@click.pass_context
def filter_run(
    ctx,
    session_id: str,
    input_file: str,
    keyword: List[str],
    regex: List[str],
    level: List[str],
    source: List[str],
    start_time: str,
    end_time: str,
    case_sensitive: bool,
    output: str,
    count: int,
    save_session: str,
):
    """Filter logs by various criteria."""
    config = ctx.obj["config"]
    no_color = ctx.obj["no_color"]
    
    entries: List[LogEntry] = []
    
    if session_id:
        session_manager = SessionManager(config.session_dir)
        session = session_manager.load_session(session_id)
        if not session:
            click.echo(f"{Fore.RED}Session not found: {session_id}{Style.RESET_ALL}", err=True)
            sys.exit(1)
        entries = session.log_entries
        click.echo(f"{Fore.BLUE}Loaded {len(entries)} entries from session {session_id}{Style.RESET_ALL}")
    elif input_file:
        from ..parsers import LogParser
        parser = LogParser()
        with open(input_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                parsed = parser.parse(line)
                if parsed:
                    entries.append(LogEntry(
                        timestamp=parsed.get("timestamp", datetime.now()),
                        source=parsed.get("source", "file"),
                        raw_message=line,
                        level=parsed.get("level", "INFO"),
                    ))
        click.echo(f"{Fore.BLUE}Loaded {len(entries)} entries from file{Style.RESET_ALL}")
    else:
        click.echo(f"{Fore.RED}Please specify --session or --input{Style.RESET_ALL}", err=True)
        sys.exit(1)
    
    filter_engine = FilterEngine()
    
    for kw in keyword:
        filter_engine.add_keyword_filter(kw, case_sensitive)
    
    for rx in regex:
        filter_engine.add_regex_filter(rx, case_sensitive)
    
    if level:
        filter_engine.add_level_filter(list(level))
    
    if source:
        filter_engine.add_source_filter(list(source))
    
    try:
        start_dt = _parse_time(start_time) if start_time else None
        end_dt = _parse_time(end_time) if end_time else None
        if start_dt or end_dt:
            filter_engine.add_time_range_filter(start_dt, end_dt)
    except click.BadParameter as e:
        click.echo(f"{Fore.RED}{e}{Style.RESET_ALL}", err=True)
        sys.exit(1)
    
    filtered = list(filter_engine.filter(iter(entries)))
    
    if count:
        filtered = filtered[:count]
    
    click.echo(f"{Fore.GREEN}Found {len(filtered)} matching entries{Style.RESET_ALL}")
    
    for entry in filtered:
        _print_entry(entry, show_source=True, no_color=no_color)
        
        if output:
            with open(output, "a", encoding="utf-8") as f:
                f.write(str(entry) + "\n")
    
    if save_session:
        session_manager = SessionManager(config.session_dir)
        session = session_manager.create_session(
            name=save_session,
            description=f"Filtered on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            log_entries=filtered,
            filter_engine=filter_engine,
        )
        session_path = session_manager.save_session(session)
        click.echo(f"{Fore.GREEN}Filtered session saved: {session.id} -> {session_path}{Style.RESET_ALL}")


@cli.group()
def alert():
    """Manage and run alert rules."""
    pass


@alert.command("list")
@click.pass_context
def alert_list(ctx):
    """List all configured alert rules."""
    config = ctx.obj["config"]
    no_color = ctx.obj["no_color"]
    
    if not config.alert_rules:
        click.echo("No alert rules configured")
        return
    
    click.echo(f"Configured {len(config.alert_rules)} alert rule(s):")
    for rule in config.alert_rules:
        color = SEVERITY_COLORS.get(rule.severity.lower(), "")
        reset = Style.RESET_ALL if not no_color else ""
        
        if no_color:
            click.echo(f"  - {rule.name}")
        else:
            click.echo(f"  {color}- {rule.name}{reset}")
        
        click.echo(f"      Pattern: {rule.pattern}")
        click.echo(f"      Type: {'regex' if rule.is_regex else 'keyword'}")
        click.echo(f"      Severity: {rule.severity}")
        click.echo(f"      Threshold: {rule.threshold} in {rule.window_seconds}s")
        click.echo(f"      Action: {rule.action}")


@alert.command("test")
@click.option("--session", "session_id", help="Session ID to test alerts against")
@click.option("--input", "-i", "input_file", help="Input log file (alternative to session)")
@click.option("--rule", "-r", multiple=True, help="Test only specific rule(s)")
@click.pass_context
def alert_test(ctx, session_id: str, input_file: str, rule: List[str]):
    """Test alert rules against collected logs."""
    config = ctx.obj["config"]
    no_color = ctx.obj["no_color"]
    
    entries: List[LogEntry] = []
    
    if session_id:
        session_manager = SessionManager(config.session_dir)
        session = session_manager.load_session(session_id)
        if not session:
            click.echo(f"{Fore.RED}Session not found: {session_id}{Style.RESET_ALL}", err=True)
            sys.exit(1)
        entries = session.log_entries
    elif input_file:
        from ..parsers import LogParser
        parser = LogParser()
        with open(input_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                parsed = parser.parse(line)
                if parsed:
                    entries.append(LogEntry(
                        timestamp=parsed.get("timestamp", datetime.now()),
                        source=parsed.get("source", "file"),
                        raw_message=line,
                        level=parsed.get("level", "INFO"),
                    ))
    else:
        click.echo(f"{Fore.RED}Please specify --session or --input{Style.RESET_ALL}", err=True)
        sys.exit(1)
    
    alert_engine = AlertEngine()
    rules_to_test = config.alert_rules
    if rule:
        rules_to_test = [r for r in config.alert_rules if r.name in rule]
    
    if not rules_to_test:
        click.echo(f"{Fore.RED}No matching alert rules found{Style.RESET_ALL}", err=True)
        sys.exit(1)
    
    alert_engine.add_rules_from_config(rules_to_test)
    
    click.echo(f"{Fore.BLUE}Testing {len(rules_to_test)} rule(s) against {len(entries)} entries...{Style.RESET_ALL}")
    
    for entry in entries:
        alert_engine.process_entry(entry)
    
    alerts = alert_engine.check_alerts()
    if alerts:
        click.echo(f"\n{Fore.YELLOW}Triggered {len(alerts)} alert(s):{Style.RESET_ALL}\n")
        for alert in alerts:
            _print_alert(alert, no_color)
    else:
        click.echo(f"{Fore.GREEN}No alerts triggered{Style.RESET_ALL}")


@cli.group()
def session():
    """Manage analysis sessions."""
    pass


@session.command("list")
@click.pass_context
def session_list(ctx):
    """List all saved sessions."""
    config = ctx.obj["config"]
    
    session_manager = SessionManager(config.session_dir)
    sessions = session_manager.list_sessions()
    
    if not sessions:
        click.echo("No saved sessions")
        return
    
    click.echo(f"Found {len(sessions)} session(s):")
    for s in sessions:
        created_at = datetime.fromisoformat(s["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
        sources = ", ".join(s["source_names"]) if s["source_names"] else "N/A"
        resumable_tag = f"{Fore.GREEN}[resumable]{Style.RESET_ALL}" if s.get("has_cursors") else ""
        click.echo(f"  {Fore.BLUE}{s['id']}{Style.RESET_ALL} - {s['name']} {resumable_tag}")
        click.echo(f"      Created: {created_at}")
        if s.get("updated_at"):
            updated_at = datetime.fromisoformat(s["updated_at"]).strftime("%Y-%m-%d %H:%M:%S")
            click.echo(f"      Updated: {updated_at}")
        if s.get("last_collected_at"):
            lc = datetime.fromisoformat(s["last_collected_at"]).strftime("%Y-%m-%d %H:%M:%S")
            click.echo(f"      Last collected: {lc}")
        if s.get("latest_log_timestamp"):
            lt = datetime.fromisoformat(s["latest_log_timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            click.echo(f"      Latest log: {lt}")
        click.echo(f"      Logs: {s['log_count']} entries")
        click.echo(f"      Sources: {sources}")
        if s["description"]:
            click.echo(f"      Description: {s['description']}")


@session.command("show")
@click.argument("session_id")
@click.option("--count", "-n", type=int, help="Show only first N entries")
@click.option("--tail", type=int, help="Show only last N entries")
@click.pass_context
def session_show(ctx, session_id: str, count: int, tail: int):
    """Show details of a specific session."""
    config = ctx.obj["config"]
    no_color = ctx.obj["no_color"]
    
    session_manager = SessionManager(config.session_dir)
    session = session_manager.load_session(session_id)
    
    if not session:
        click.echo(f"{Fore.RED}Session not found: {session_id}{Style.RESET_ALL}", err=True)
        sys.exit(1)
    
    created_at = session.created_at.strftime("%Y-%m-%d %H:%M:%S")
    sources = ", ".join(session.source_names) if session.source_names else "N/A"
    
    click.echo(f"{Fore.BLUE}Session: {session.id} - {session.name}{Style.RESET_ALL}")
    click.echo(f"  Created: {created_at}")
    click.echo(f"  Description: {session.description}")
    click.echo(f"  Logs: {len(session.log_entries)} entries")
    click.echo(f"  Sources: {sources}")
    if session.start_time:
        click.echo(f"  Start time: {session.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    if session.end_time:
        click.echo(f"  End time: {session.end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    entries = session.log_entries
    if tail:
        entries = entries[-tail:]
    elif count:
        entries = entries[:count]
    
    if session.source_cursors:
        click.echo(f"\n{Fore.BLUE}Source cursors (for resume):{Style.RESET_ALL}")
        for src, cur in session.source_cursors.items():
            ts_str = cur.last_timestamp.strftime("%Y-%m-%d %H:%M:%S") if cur.last_timestamp else "N/A"
            click.echo(f"  - {src}: latest={ts_str}, offset={cur.last_offset}")
    
    if entries:
        click.echo(f"\n{Fore.BLUE}Log entries:{Style.RESET_ALL}")
        for entry in entries:
            _print_entry(entry, show_source=True, no_color=no_color)


@session.command("resume")
@click.argument("session_id")
@click.option("--source", "-s", multiple=True, help="Resume only specific source(s)")
@click.option("--end-time", "-e", help="End time for incremental collection")
@click.option("--follow", "-f", is_flag=True, help="Follow log output in real-time after resume")
@click.option("--output", "-o", help="Output file path to append new logs")
@click.option("--no-filter", is_flag=True, help="Do not apply saved filters")
@click.option("--no-alert", is_flag=True, help="Do not apply saved alert engine")
@click.option("--no-save", is_flag=True, help="Do not update the session (dry run)")
@click.pass_context
def session_resume(
    ctx,
    session_id: str,
    source: List[str],
    end_time: str,
    follow: bool,
    output: str,
    no_filter: bool,
    no_alert: bool,
    no_save: bool,
):
    """Resume analysis from a saved session (incremental collection + state preservation)."""
    config = ctx.obj["config"]
    no_color = ctx.obj["no_color"]

    session_manager = SessionManager(config.session_dir)
    session = session_manager.load_session(session_id)
    if not session:
        click.echo(f"{Fore.RED}Session not found: {session_id}{Style.RESET_ALL}", err=True)
        sys.exit(1)

    try:
        end_dt = _parse_time(end_time) if end_time else None
    except click.BadParameter as e:
        click.echo(f"{Fore.RED}{e}{Style.RESET_ALL}", err=True)
        sys.exit(1)

    source_names_to_use = list(source) if source else list(session.source_names)
    sources = _create_sources_from_config(config, source_names_to_use)
    if not sources:
        click.echo(f"{Fore.RED}No valid sources to resume{Style.RESET_ALL}", err=True)
        sys.exit(1)

    existing_count = len(session.log_entries)
    click.echo(f"{Fore.BLUE}Resuming session {session_id} ('{session.name}'){Style.RESET_ALL}")
    click.echo(f"  Existing logs: {existing_count} entries")
    click.echo(f"  Sources: {', '.join(source_names_to_use)}")
    latest_ts = session.get_latest_timestamp()
    if latest_ts:
        click.echo(f"  Last known timestamp: {latest_ts.strftime('%Y-%m-%d %H:%M:%S')}")

    source_cursors = session_manager.build_source_cursors(session)
    for src_name in list(source_cursors.keys()):
        if src_name not in source_names_to_use:
            del source_cursors[src_name]
    for s in sources:
        if s.name not in source_cursors:
            source_cursors[s.name] = {}

    aggregator = LogAggregator(sources)

    filter_engine = session.filter_engine if (session.filter_engine and not no_filter) else FilterEngine()
    alert_engine = session.alert_engine if (session.alert_engine and not no_alert) else AlertEngine()
    if not session.alert_engine or no_alert:
        alert_engine.add_rules_from_config(config.alert_rules)

    new_alerts_before = set(id(a) for a in alert_engine.check_alerts()) if not no_alert else set()
    if not no_alert:
        alert_engine.add_alert_callback(lambda a: _print_alert(a, no_color))

    new_entries: List[LogEntry] = []
    latest_cursors: Dict[str, Dict[str, Any]] = dict(source_cursors)

    try:
        log_stream = aggregator.aggregate_incremental(source_cursors, end_dt, follow)
        def _wrap():
            nonlocal latest_cursors
            for entry, cursor_map in log_stream:
                for src, cur in cursor_map.items():
                    latest_cursors[src] = cur
                yield entry
        stream = _wrap()
        if not no_filter:
            stream = filter_engine.filter(stream)
        if not no_alert:
            stream = alert_engine.process_entries(stream)

        for entry in stream:
            new_entries.append(entry)
            _print_entry(entry, show_source=True, no_color=no_color)
            if output:
                with open(output, "a", encoding="utf-8") as f:
                    f.write(str(entry) + "\n")
    except KeyboardInterrupt:
        click.echo(f"\n{Fore.YELLOW}Interrupted by user{Style.RESET_ALL}")
    finally:
        click.echo(f"\n{Fore.BLUE}Resume summary:{Style.RESET_ALL}")
        click.echo(f"  Existing entries: {existing_count}")
        click.echo(f"  New entries (after dedup): {len(new_entries)}")

        if not no_save and new_entries:
            from ..session.manager import SourceCursor
            added = session_manager.apply_incremental_result(session, new_entries, latest_cursors)
            session.filter_engine = filter_engine
            session.alert_engine = alert_engine
            if end_dt:
                session.end_time = end_dt
            session_path = session_manager.save_session(session)
            click.echo(f"  {Fore.GREEN}Session updated: {len(added)} new entries merged{Style.RESET_ALL}")
            click.echo(f"    File: {session_path}")
        elif not no_save and not new_entries:
            click.echo(f"  {Fore.YELLOW}No new entries; session not modified{Style.RESET_ALL}")

        if not no_alert:
            all_alerts = alert_engine.check_alerts()
            new_triggered = [a for a in all_alerts if id(a) not in new_alerts_before]
            if new_triggered:
                click.echo(f"  {Fore.YELLOW}New alerts triggered during resume: {len(new_triggered)}{Style.RESET_ALL}")


@session.command("delete")
@click.argument("session_id")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
@click.pass_context
def session_delete(ctx, session_id: str, yes: bool):
    """Delete a session."""
    config = ctx.obj["config"]
    
    session_manager = SessionManager(config.session_dir)
    
    if not yes:
        click.confirm(f"Are you sure you want to delete session {session_id}?", abort=True)
    
    if session_manager.delete_session(session_id):
        click.echo(f"{Fore.GREEN}Session {session_id} deleted{Style.RESET_ALL}")
    else:
        click.echo(f"{Fore.RED}Session not found: {session_id}{Style.RESET_ALL}", err=True)
        sys.exit(1)


@session.command("export")
@click.argument("session_id")
@click.option("--output", "-o", required=True, help="Output file path")
@click.option("--format", "-f", type=click.Choice(["json", "text", "csv"]), default="text", help="Output format")
@click.pass_context
def session_export(ctx, session_id: str, output: str, format: str):
    """Export session data to a file."""
    config = ctx.obj["config"]
    
    session_manager = SessionManager(config.session_dir)
    session = session_manager.load_session(session_id)
    
    if not session:
        click.echo(f"{Fore.RED}Session not found: {session_id}{Style.RESET_ALL}", err=True)
        sys.exit(1)
    
    if format == "json":
        import json
        data = session.to_dict()
        with open(output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    elif format == "csv":
        import csv
        with open(output, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "source", "level", "message"])
            for entry in session.log_entries:
                writer.writerow([
                    entry.timestamp.isoformat(),
                    entry.source,
                    entry.level,
                    entry.raw_message,
                ])
    else:
        with open(output, "w", encoding="utf-8") as f:
            for entry in session.log_entries:
                f.write(str(entry) + "\n")
    
    click.echo(f"{Fore.GREEN}Session exported to {output}{Style.RESET_ALL}")


def main():
    cli(obj={})


if __name__ == "__main__":
    main()
