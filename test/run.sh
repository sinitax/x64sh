#!/bin/sh

# Test runner for x64sh
# Runs each test/*.asm file through x64sh -q and compares output
# against the corresponding test/*.expected file.
#
# Exit 0 if all tests pass, 1 if any fail.

X64SH="${X64SH:-./build/x64sh}"
TESTDIR="$(dirname "$0")"
PASS=0
FAIL=0
SKIP=0

if [ ! -x "$X64SH" ]; then
	echo "ERROR: $X64SH not found or not executable (run make first)"
	exit 1
fi

for asmfile in "$TESTDIR"/*.asm; do
	name="$(basename "$asmfile" .asm)"
	expected="$TESTDIR/$name.expected"
	checkfile="$TESTDIR/$name.check"

	if [ ! -f "$checkfile" ]; then
		echo "SKIP $name (no .check file)"
		SKIP=$((SKIP + 1))
		continue
	fi

	# Run the assembly through x64sh
	output=$("$X64SH" -q < "$asmfile" 2>&1)

	# Run each check line against the output
	# Check file format: each line is a grep -E pattern that must match
	test_fail=0
	lineno=0
	while IFS= read -r pattern; do
		lineno=$((lineno + 1))

		# skip blank lines and comments
		case "$pattern" in
			""|\#*) continue ;;
		esac

		if ! echo "$output" | grep -qE "$pattern"; then
			if [ $test_fail -eq 0 ]; then
				echo "FAIL $name"
				test_fail=1
			fi
			echo "  line $lineno: pattern not matched: $pattern"
		fi
	done < "$checkfile"

	if [ $test_fail -eq 1 ]; then
		FAIL=$((FAIL + 1))
		echo "  --- full output ---"
		echo "$output" | sed 's/^/  | /'
		echo "  ---"
	else
		echo "PASS $name"
		PASS=$((PASS + 1))
	fi
done

echo ""
echo "$PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
