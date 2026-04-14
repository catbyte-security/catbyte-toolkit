#!/usr/bin/env python3
"""Evaluate an LLDB expression in a stopped process context.

Runs under system Python with LLDB module.
Usage: lldb_eval.py <pid> <expression>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from lldb_common import (
    emit_json, emit_error, create_debugger,
    attach_to_pid, cleanup_process, cleanup_debugger,
    setup_timeout, cancel_timeout,
)


def main():
    if len(sys.argv) < 3:
        emit_error("Usage: lldb_eval.py <pid> <expression>")
        sys.exit(1)

    pid = int(sys.argv[1])
    expression = sys.argv[2]

    dbg = None
    process = None

    setup_timeout(25)

    try:
        import lldb
        dbg = create_debugger()
        target = dbg.CreateTarget("")
        process = attach_to_pid(target, pid)

        # Get the first thread's first frame for evaluation context
        thread = process.GetSelectedThread()
        if not thread.IsValid():
            if process.GetNumThreads() > 0:
                thread = process.GetThreadAtIndex(0)
            else:
                emit_error("No threads available in process")
                sys.exit(1)

        frame = thread.GetFrameAtIndex(0)
        if not frame.IsValid():
            emit_error("No valid frame for expression evaluation")
            sys.exit(1)

        # Evaluate expression
        options = lldb.SBExpressionOptions()
        options.SetTimeoutInMicroSeconds(10 * 1000000)  # 10 second timeout
        options.SetUnwindOnError(True)
        options.SetTryAllThreads(False)

        result = frame.EvaluateExpression(expression, options)

        if result.GetError().Fail():
            error_str = result.GetError().GetCString()
            cancel_timeout()
            emit_json({
                "pid": pid,
                "expression": expression,
                "success": False,
                "error": error_str,
            })
        else:
            value = result.GetValue()
            summary = result.GetSummary()
            type_name = result.GetTypeName()
            num_children = result.GetNumChildren()

            # Collect child values for aggregate types
            children = []
            if num_children > 0 and num_children <= 50:
                for i in range(num_children):
                    child = result.GetChildAtIndex(i)
                    if child.IsValid():
                        children.append({
                            "name": child.GetName(),
                            "value": child.GetValue(),
                            "type": child.GetTypeName(),
                            "summary": child.GetSummary(),
                        })

            cancel_timeout()
            emit_json({
                "pid": pid,
                "expression": expression,
                "success": True,
                "value": value,
                "summary": summary,
                "type": type_name,
                "children": children if children else None,
            })

    except Exception as e:
        cancel_timeout()
        emit_error(str(e))
        sys.exit(1)
    finally:
        if process:
            cleanup_process(process, detach=True)
        if dbg:
            cleanup_debugger(dbg)


if __name__ == "__main__":
    main()
