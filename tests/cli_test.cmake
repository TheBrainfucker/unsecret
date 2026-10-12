# Runs the real program on made-up folders and checks exit codes and output.
# Needs: UNSECRET (the program), WORK_DIR (a scratch folder).

file(REMOVE_RECURSE "${WORK_DIR}")
file(MAKE_DIRECTORY "${WORK_DIR}/clean" "${WORK_DIR}/leaky/sub")
file(WRITE "${WORK_DIR}/clean/a.txt" "nothing to see\n")

# Split so the repo never holds a whole key.
set(key "AKIA")
string(APPEND key "IOSFODNN7EXAMPLE")
file(WRITE "${WORK_DIR}/leaky/sub/config.py" "x = 1\r\naws_key = \"${key}\"\r\n")

function(run name expected_code)
    execute_process(COMMAND "${UNSECRET}" ${ARGN}
        RESULT_VARIABLE code OUTPUT_VARIABLE out ERROR_VARIABLE err)
    if(NOT code EQUAL expected_code)
        message(FATAL_ERROR "${name}: exit ${code}, expected ${expected_code}\n${out}${err}")
    endif()
    set(out "${out}" PARENT_SCOPE)
    set(err "${err}" PARENT_SCOPE)
endfunction()

function(expect name text haystack)
    string(FIND "${haystack}" "${text}" at)
    if(at EQUAL -1)
        message(FATAL_ERROR "${name}: missing '${text}' in:\n${haystack}")
    endif()
endfunction()

run(clean 0 "${WORK_DIR}/clean")
expect(clean "no findings (scanned 1 file" "${err}")

run(leaky 1 "${WORK_DIR}/leaky")
expect(leaky "sub/config.py:2:12 [aws-access-key-id] AKIA********" "${out}")
expect(leaky "1 finding in 1 file" "${err}")
string(FIND "${out}${err}" "${key}" at)
if(NOT at EQUAL -1)
    message(FATAL_ERROR "leaky: the full key was printed")
endif()

run(missing 2 "${WORK_DIR}/missing")
run(usage 2)
