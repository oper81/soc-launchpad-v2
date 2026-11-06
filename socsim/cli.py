"""Единая точка входа: generate/detect/evaluate/queue/replay/demo."""
import argparse
import json
import os
import sys

from . import __version__


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="socsim", description="Synthetic SOC lab telemetry")
    p.add_argument("--version", action="version", version="socsim " + __version__)
    sub = p.add_subparsers(dest="command")

    sub.add_parser("version", help="показать версию")

    g = sub.add_parser("generate", help="сгенерировать сценарий")
    g.add_argument("--scenario", required=True)
    g.add_argument("--out", default="labs")

    d = sub.add_parser("detect", help="офлайн-детектор")
    d.add_argument("--events", required=True)
    d.add_argument("--out", default=os.path.join("labs", "alerts.jsonl"))
    d.add_argument("--tuning", action="store_true", help="включить исключения для ловушек")

    e = sub.add_parser("evaluate", help="оценка алертов и вердиктов")
    e.add_argument("--alerts", required=True)
    e.add_argument("--events", required=True)
    e.add_argument("--truth", required=True)
    e.add_argument("--verdicts", default=None)

    q = sub.add_parser("queue", help="очередь алертов для L1 + шаблон verdicts.csv")
    q.add_argument("--alerts", required=True)
    q.add_argument("--verdicts", default=os.path.join("labs", "verdicts.csv"))

    r = sub.add_parser("replay", help="проиграть events.jsonl")
    r.add_argument("--events", required=True)
    r.add_argument("--speed", type=float, default=1.0)
    r.add_argument("--max-gap", type=float, default=5.0)
    r.add_argument("--only-host", default=None)
    r.add_argument("--start-at", default=None)

    dm = sub.add_parser("demo", help="полный конвейер на мини-сценарии")
    dm.add_argument("--tuning", action="store_true")
    return p


def _cmd_generate(args) -> int:
    from .generate import generate
    m = generate(args.scenario, args.out)
    print(json.dumps(m, ensure_ascii=False, indent=2))
    return 0


def _cmd_detect(args) -> int:
    from .detect import detect
    res = detect(args.events, args.out, tuning=args.tuning)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0


def _cmd_evaluate(args) -> int:
    from .evaluate import evaluate
    r = evaluate(args.alerts, args.events, args.truth, args.verdicts)
    print(json.dumps(r, ensure_ascii=False, indent=2))
    return 0


def _cmd_queue(args) -> int:
    from .queue import build_queue
    r = build_queue(args.alerts, args.verdicts)
    print(r["queue_text"])
    print("\nverdicts template: %s" % r["verdicts_path"])
    return 0


def _cmd_replay(args) -> int:
    from .replay import replay
    replay(args.events, speed=args.speed, max_gap=args.max_gap,
           only_host=args.only_host, start_at=args.start_at)
    return 0


def _cmd_demo(args) -> int:
    from .generate import generate
    from .detect import detect
    from .evaluate import evaluate
    out = os.path.join("labs", "demo")
    os.makedirs(out, exist_ok=True)
    scenario = os.path.join("scenarios", "demo.json")
    m = generate(scenario, out)
    print("generate:", m["total_events"], "events")
    d = detect(os.path.join(out, "events.jsonl"), os.path.join(out, "alerts.jsonl"),
               tuning=args.tuning)
    print("detect:", d["total_alerts"], "alerts")
    r = evaluate(os.path.join(out, "alerts.jsonl"),
                 os.path.join(out, "events.jsonl"),
                 os.path.join(out, "groundtruth.jsonl"))
    print("evaluate:", json.dumps({"campaigns_detected": r["campaigns_detected"],
                                   "campaigns_total": r["campaigns_total"],
                                   "precision": r["precision"]}, ensure_ascii=False))
    return 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command in (None, "version"):
        print("socsim " + __version__)
        return 0
    dispatch = {
        "generate": _cmd_generate, "detect": _cmd_detect, "evaluate": _cmd_evaluate,
        "queue": _cmd_queue, "replay": _cmd_replay, "demo": _cmd_demo,
    }
    fn = dispatch.get(args.command)
    if fn is None:
        print("unknown command: %r" % args.command, file=sys.stderr)
        return 2
    return fn(args)


if __name__ == "__main__":
    sys.exit(main())