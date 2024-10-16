from datetime import datetime, timezone
import json
import os
from typing import Any, Literal
from dataclasses import dataclass, field
from urllib.parse import urlparse
from uuid import UUID
import requests
import argparse
from pathlib import Path


@dataclass
class Settings:
    project_id: UUID
    hosts: list[str]
    all_: bool
    ext: Literal["html", "pdf"]
    hidden: bool
    access_token: str
    api_url: str
    auth_headers: dict[str, Any] = field(init=False)
    project_name: str = ""

    def __post_init__(self):
        self.auth_headers = {"Authorization": self.access_token}


@dataclass
class WorkPaths:
    reports_dir: Path
    info_file: Path


def get_settings(args: argparse.Namespace) -> Settings:
    project_id = None
    hosts = None
    all_ = None
    try:
        project_id = UUID(args.project)
    except ValueError:
        raise ValueError("Неверный UUID проекта")

    if args.ext not in ("html", "pdf"):
        raise ValueError("Неверный тип отчета")

    if args.hosts == "all":
        hosts = []
        all_ = True
    else:
        hosts = args.hosts.split(",")
        all_ = False

    _token = os.environ.get("SF_ACCESS_TOKEN", None)
    if not _token:
        raise ValueError("env переменная 'SF_ACCESS_TOKEN' не установлена.")

    _token = f'Bearer {_token.replace("Bearer", "").replace("bearer", "").strip()}'

    _api_url = os.environ.get("SF_API_URL", None)
    if not _api_url:
        raise ValueError("env переменная 'SF_API_URL' не установлена.")
    parsed_url = urlparse(_api_url)
    if not parsed_url.scheme or parsed_url.scheme != "https" or not parsed_url.netloc:
        raise ValueError("Неверный формат URL в переменной 'SF_API_URL'")
    if parsed_url.path.strip("/") != "api":
        raise ValueError("Неверный формат URL в переменной 'SF_API_URL'")

    if _api_url.endswith("api"):
        _api_url += "/"
    return Settings(
        project_id=project_id,
        hosts=hosts,
        all_=all_,
        ext=args.ext,
        hidden=args.hidden,
        access_token=_token,
        api_url=_api_url,
    )


RESTRICTED_SYMBOLS = r"""!"#$%&'()*+,./:;<=>?@[\]^`{|}~"""


def cleanup_name(name: str) -> str:
    for char in RESTRICTED_SYMBOLS:
        name = name.replace(char, "")
    name = name.replace(" ", "-")
    return name


def init_paths(settings: Settings) -> WorkPaths:
    reports_path = Path(f"REPORTS_{cleanup_name(settings.project_name)}")
    reports_path.mkdir(exist_ok=True)
    current_reports = (
        reports_path
        / f'{settings.ext.upper()} {datetime.now(tz=timezone.utc).strftime("%d.%m.%Y %H.%M")} UTC'
    )
    current_reports.mkdir(exist_ok=True)
    info_file = current_reports / "info.json"
    info_file.touch(exist_ok=True)
    return WorkPaths(
        reports_dir=current_reports,
        info_file=info_file,
    )


def update_project_name(settings: Settings) -> None:
    r = requests.get(
        f"{settings.api_url}projects/{settings.project_id}",
        timeout=10,
        headers=settings.auth_headers,
    )
    response = r.json()
    settings.project_name = response["name"]


def get_hosts(settings: Settings) -> list[str]:
    alive = "alive=1&hidden=0" if not settings.hidden else "&alive=0&hidden=1"
    r = requests.get(
        f"{settings.api_url}hosts/?{alive}&project_id={settings.project_id}&limit=2000",
        timeout=30,
        headers=settings.auth_headers,
    )
    response = r.json()
    return [host["ipv4"] for host in response["items"]]


def download_report(settings: Settings, host: str) -> bytes:
    host_id = f"{settings.project_id}@{host}"
    r = requests.get(
        f"{settings.api_url}hosts/{host_id}/report",
        timeout=300,
        headers=settings.auth_headers
        | {"Accept": "application/pdf" if settings.ext == "pdf" else "text/html"},
    )
    return r.content


def save_report(settings: Settings, paths: WorkPaths, host: str, report: bytes) -> None:
    with open(paths.reports_dir / f"{host}.{settings.ext}", "wb") as f:
        f.write(report)


def save_stats(paths: WorkPaths, stats: dict[str, list[str]]) -> None:
    with open(paths.info_file, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--project",
        help="UUID Проекта",
        required=True,
    )
    parser.add_argument(
        "--hosts",
        help="Хосты, по которым требуется скачать отчет через запятую. 'all', если требуется по всем",
        type=str,
        required=True,
    )
    parser.add_argument(
        "--ext",
        help="Тип отчета 'html' или 'pdf'. HTML скачивается в разы быстрее",
        type=str,
        required=True,
    )
    parser.add_argument(
        "--hidden",
        help="Отчеты только по скрытым хостам (hidden=true). По умолчанию отчеты только по открытым хостам",
        action="store_true",
        default=False,
    )

    args = parser.parse_args()

    settings = get_settings(args)
    update_project_name(settings)
    paths = init_paths(settings)
    hosts = get_hosts(settings)

    if not settings.all_:
        exc = set(settings.hosts) - set(hosts)
        if exc:
            not_found = "\n".join(exc)
            print(
                f"Некоторые {'активные' if not settings.hidden else 'неактивные'} хосты не найдены в проекте {settings.project_name}.\n"
                "Отчеты по ним не будут скачаны:\n"
                f"{not_found}"
            )
        settings.hosts = list(set(settings.hosts) & set(hosts))
    else:
        settings.hosts = hosts

    q = input(
        f"Скачивание {'PDF' if settings.ext == 'pdf' else 'HTML'} отчетов будет производиться по порядку для {len(settings.hosts)} хостов. Продолжить (y): "
    )
    if q != "y":
        return

    stats = {
        "OK": [],
        "ERROR": [],
    }
    current = 1
    total = len(settings.hosts)
    for host in settings.hosts:
        try:
            print(f"Скачивание отчета для {host}. {current}/{total}")
            report = download_report(settings, host)
            save_report(settings, paths, host, report)
            print(f"Отчет для {host} сохранен")
        except Exception as e:
            print(f"Ошибка при скачивании отчета для {host}: {e}")
            stats["ERROR"].append(f"{host}: {e}")
        else:
            stats["OK"].append(host)
        current += 1

    save_stats(paths, stats)
    print(
        f"Скачивание завершено. Отчеты можно посмотреть в папке {paths.reports_dir}. Файл с ошибками лежит в {paths.info_file}"
    )


if __name__ == "__main__":
    main()
