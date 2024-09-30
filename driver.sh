#!/bin/sh
# 테스트 목록
alarm_tests=" \
alarm-single \
alarm-multiple \
alarm-simultaneous \
alarm-priority \
alarm-zero \
alarm-negative \
"
priority_tests=" \
priority-change \
priority-donate-one \
priority-donate-multiple \
priority-donate-multiple2 \
priority-donate-nest \
priority-donate-sema \
priority-donate-lower \
priority-donate-chain \
priority-fifo \
priority-preempt \
priority-sema \
priority-condvar \
"
mlfqs_tests=" \
mlfqs-load-1 \
mlfqs-load-60 \
mlfqs-load-avg \
mlfqs-recent-1 \
mlfqs-fair-2 \
mlfqs-fair-20 \
mlfqs-nice-2 \
mlfqs-nice-10 \
mlfqs-block \
"
# 특정 테스트가 목록에 있는지 확인하는 함수
contains() {
    case " $1 " in
        *" $2 "*) return 0 ;;
        *) return 1 ;;
    esac
}
# 인자를 검사하여 실행할 테스트를 결정
if [ "$1" = "alarm" ]; then
    selected_tests="$alarm_tests"
    test_prefix="threads"
elif [ "$1" = "priority" ]; then
    selected_tests="$priority_tests"
    test_prefix="threads"
elif [ "$1" = "mlfqs" ]; then
    selected_tests="$mlfqs_tests"
    test_prefix="threads/mlfqs"
elif [ -n "$1" ]; then
    # 입력 인자를 테스트 이름으로 취급
    selected_tests="$1"
    # 테스트가 mlfqs_tests에 있는지 확인하여 test_prefix 결정
    if contains "$mlfqs_tests" "$1"; then
        test_prefix="threads/mlfqs"
    else
        test_prefix="threads"
    fi
else
    echo "Usage: $0 {alarm|priority|mlfqs|test_name}"
    exit 1
fi
# 빌드 작업 수행
cd threads && make clean && make && cd build || exit
# Pintos 실행 및 진행 상황 출력
count=1
total=$(echo "$selected_tests" | wc -w)
for test in $selected_tests; do
    if contains "$mlfqs_tests" "$test"; then
        echo "Running test $count of $total (MLFQS): $test"
        pintos -v -k -T 480 -m 20 -- -q -mlfqs run "$test" < /dev/null 2> "tests/$test_prefix/$test.errors" > "tests/$test_prefix/$test.output"
    else
        echo "Running test $count of $total: $test"
        pintos -v -k -T 60 -m 20 -- -q run "$test" < /dev/null 2> "tests/$test_prefix/$test.errors" > "tests/$test_prefix/$test.output"
    fi
    count=$((count + 1))
done
# Perl 체크 및 진행 상황 출력
count=1
for test in $selected_tests; do
    echo "Running Perl check $count of $total: $test"
    perl -I../.. ../../tests/"$test_prefix"/"$test".ck tests/"$test_prefix"/"$test" tests/"$test_prefix"/"$test".result
    count=$((count + 1))
done