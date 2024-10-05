#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

// 프로세스가 종료될 때 정리 작업을 수행하는 함수
static void process_cleanup (void);

// 사용자 프로그램을 로드하기 위한 함수. file_name을 로드하여 intr_frame에 저장된 CPU 상태를 설정한다.
static bool load (const char *file_name, struct intr_frame *if_);

// 초기 프로세스를 실행하기 위한 함수로, 첫 번째 사용자 프로세스(initd)를 시작할 때 사용됨
static void initd (void *f_name);

// 현재 프로세스의 복제를 수행하는 내부 함수
static void __do_fork (void *);

/* 프로세스 초기화를 위한 함수. 현재 실행 중인 스레드의 정보를 초기화한다. */
static void
process_init (void) {
    struct thread *current = thread_current (); // 현재 실행 중인 스레드를 가져옴
}

/* initd라는 첫 사용자 프로그램을 FILE_NAME으로부터 로드하고 실행.
 * 새로운 스레드가 스케줄링될 수 있으며, process_create_initd()가 반환되기 전에 종료될 수도 있음.
 * initd의 스레드 ID를 반환하거나, 스레드를 생성할 수 없으면 TID_ERROR를 반환.
 * 주의: 이 함수는 단 한 번만 호출되어야 함. */
tid_t
process_create_initd (const char *file_name) {
    char *fn_copy;
    tid_t tid;

    /* FILE_NAME의 사본을 만듦.
     * load()와 호출자 간의 경쟁 상태를 방지하기 위함. */
    fn_copy = palloc_get_page (0);
    if (fn_copy == NULL)
        return TID_ERROR;
    strlcpy (fn_copy, file_name, PGSIZE);

    /* FILE_NAME을 실행할 새로운 스레드를 생성함. */
    tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
    if (tid == TID_ERROR)
        palloc_free_page (fn_copy);
    return tid;
}

/* 첫 사용자 프로세스를 시작하는 스레드 함수.
 * f_name: initd로 실행할 파일 이름. */
static void
initd (void *f_name) {
#ifdef VM
    // 가상 메모리 시스템이 활성화된 경우, 현재 스레드의 보조 페이지 테이블을 초기화
    supplemental_page_table_init (&thread_current ()->spt);
#endif

    process_init ();  // 프로세스 초기화 수행

    // 사용자 프로세스 실행에 실패할 경우 시스템 패닉을 일으킴
    if (process_exec (f_name) < 0)
        PANIC("Fail to launch initd\n");
    NOT_REACHED ();  // 이 코드에 도달하지 않아야 함
}

//*process_fork를 통해 프로세스가 복제되더라도, 커널 내부에서는 새로운 스레드가 하나 더 생성된다고 이해
/* 현재 프로세스를 'name'으로 복제하여 새 프로세스를 생성.
 * 새로운 프로세스의 스레드 ID를 반환하거나, 생성할 수 없으면 TID_ERROR를 반환. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
    /* 현재 스레드를 복제하여 새로운 스레드를 생성 */
    return thread_create (name, PRI_DEFAULT, __do_fork, thread_current ());
}

#ifndef VM
/* 부모의 주소 공간을 복제하기 위해 pml4_for_each에 전달되는 함수.
 * 프로젝트 2에서만 사용됨. */ //?
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) { //page table entry
    struct thread *current = thread_current ();
    struct thread *parent = (struct thread *) aux;
    void *parent_page;
    void *newpage;
    bool writable;

    /* 1. 만약 parent_page가 커널 페이지일 경우 즉시 반환해야 함. */

    /* 2. 부모의 pml4에서 VA에 해당하는 페이지를 확인하여 parent_page에 할당. */
    parent_page = pml4_get_page (parent->pml4, va);

    /* 3. 자식 프로세스를 위한 PAL_USER 페이지를 할당하고 결과를 NEWPAGE에 저장. */

    /* 4. 부모의 페이지를 새로운 페이지로 복제하고,
     * 부모의 페이지가 쓰기 가능인지 확인하여 WRITABLE을 설정. */

    /* 5. 자식의 페이지 테이블에 VA 주소로 새로운 페이지를 WRITABLE 권한으로 추가. */
    if (!pml4_set_page (current->pml4, va, newpage, writable)) {
        /* 6. 페이지 추가 실패 시, 에러 처리 수행. */
    }
    return true;
}
#endif

/* 부모의 실행 컨텍스트를 복사하는 스레드 함수.
 * 주의: parent->tf는 프로세스


/* 부모 프로세스의 실행 컨텍스트를 복사하여 새로운 자식 프로세스를 생성하는 함수.
 * 주의) 부모의 `parent->tf`는 프로세스의 사용자 모드 실행 컨텍스트를 포함하지 않음.
 *       즉, 이 함수에서는 `process_fork`의 두 번째 인자로 전달된 `if_`를 사용해야 함. */
static void
__do_fork (void *aux) {
    struct intr_frame if_;  // 인터럽트 프레임을 저장할 구조체 변수
    struct thread *parent = (struct thread *) aux;  // 부모 스레드 정보
    struct thread *current = thread_current ();  // 현재 스레드 정보
    struct intr_frame *parent_if;  // 부모의 인터럽트 프레임
    bool succ = true;  // 성공 여부를 저장하는 변수

    /* 1. 부모의 CPU 컨텍스트를 자식의 로컬 스택에 복사. */
    memcpy (&if_, parent_if, sizeof (struct intr_frame));

    /* 2. 부모의 페이지 테이블을 자식에게 복제 (PT: Page Table). */
    current->pml4 = pml4_create();  // 새로운 페이지 테이블 생성
    if (current->pml4 == NULL)
        goto error;  // 페이지 테이블 생성 실패 시 오류 처리

    process_activate (current);  // 현재 스레드에 대해 페이지 테이블 활성화
#ifdef VM
    /* 자식의 보조 페이지 테이블(spt)을 초기화하고 부모의 보조 페이지 테이블을 복사. */
    supplemental_page_table_init (&current->spt);
    if (!supplemental_page_table_copy (&current->spt, &parent->spt))
        goto error;  // 복사 실패 시 오류 처리
#else
    /* 부모의 페이지 테이블 엔트리를 자식의 페이지 테이블로 복제. */
    if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
        goto error;  // 복사 실패 시 오류 처리
#endif

    /* TODO: 파일 디스크립터와 같은 부모의 자원을 복제하는 코드 작성.
     * 힌트) 파일 복제는 `file_duplicate`를 사용할 수 있으며, 이는 include/filesys/file.h에 정의되어 있음.
     * 부모가 fork() 호출로부터 성공적으로 자식 프로세스의 자원을 복제하기 전에는 복제 작업을 종료하면 안 됨. */

    process_init ();  // 자식 프로세스 초기화

    /* 최종적으로 새로운 프로세스 실행 */
    if (succ)
        do_iret (&if_);  // 인터럽트 프레임을 이용하여 새 프로세스로 전환
error:
    thread_exit ();  // 오류 발생 시 스레드 종료
}

/* 주어진 사용자 프로그램을 실행하기 위해 현재 실행 컨텍스트를 f_name으로 변경.
 * 실패 시 -1을 반환한다. */
int
process_exec (void *f_name) { //TODO : parsing 기능 구현
// f_name은 문자열인데 위에서 (void *)로 넘겨받음! -> 문자열로 인식하기 위해서 char * 로 변환해줘야.
    char *file_name = f_name;  // 실행할 파일 이름
    bool success;  // 로드 성공 여부를 저장할 변수

	// ? 기존 코드 start ::
    // /* 현재 스레드 구조체의 intr_frame을 사용할 수 없음.
    //  * 이는 현재 스레드가 재스케줄링될 때 실행 정보가 해당 멤버에 저장되기 때문. */ //TODO :==========
    // struct intr_frame _if;//_if : CPU의 레지스터 상태를 저장하는 데 사용
	// //_if는 인터럽트 서비스 루틴이나 컨텍스트 스위칭 발생 시 현재 상태를 보존하거나 복원을 위해 사용
	// // 아래는 세그먼트 레지스터이다.
    // _if.ds = _if.es = _if.ss = SEL_UDSEG;  // 데이터 ,엑스트라, 스택 세그먼트 설정(메모리 세그먼트 정의)
    // _if.cs = SEL_UCSEG;  // 코드 세그먼트 설정(현재 실행 중인 코드의 메모리 세그먼트를 가리킴)
    // _if.eflags = FLAG_IF | FLAG_MBS;  // CPU의 인터럽트 플래그 및 마법 비트 설정
	// //현재 CPU의 상태를 나타냄(인터럽트 허용, I/O권한 레벨 등)

    // /* 현재 실행 중인 프로세스의 컨텍스트 제거 */
    // process_cleanup ();
	// ? 기존 코드 end ::

    /* 바이너리 파일을 로드하고 초기화 */
    success = load (file_name, &_if); //적재 성공 시 1, 실패 시 0을 반환

    /* 로드에 실패한 경우 프로그램 종료 */
	// file_name은 프로그램 파일을 받기 위해 만든 임시 변수(load가 끝나면 메모리를 반환)
    // palloc은 load()함수 내에서 file_name을 메모리에 올리는 과정에서 page allocation을 임시로 시행.
	// => free가 필요
	palloc_free_page (file_name);
    if (!success)
        return -1;

    /* 성공적으로 로드되었으면 프로세스 실행(context switching) */
    do_iret (&_if);
    NOT_REACHED ();
}

/* 주어진 TID에 해당하는 자식 프로세스가 종료될 때까지 기다리고, 해당 자식의 종료 상태를 반환.
 * 자식이 커널에 의해 종료된 경우(예: 예외로 인해 종료된 경우) -1을 반환.
 * TID가 유효하지 않거나 주어진 TID가 호출 프로세스의 자식이 아닌 경우, 혹은 이미 process_wait()를 호출한 경우,
 * 즉시 -1을 반환하며, 대기하지 않음.
 *
 * 이 함수는 problem 2-2에서 구현될 예정.
 * 현재는 아무 작업도 수행하지 않음. */
int
process_wait (tid_t child_tid UNUSED) {
    /* XXX: 현재 pintos는 process_wait(initd)를 호출할 때 종료되므로,
     * XXX: 여기에 무한 루프를 추가하여 process_wait를 구현하기 전에 대기할 수 있도록 권장. */
    return -1;
}

/* 현재 프로세스를 종료. 이 함수는 thread_exit()에 의해 호출됨. */
void
process_exit (void) {
    struct thread *curr = thread_current ();
    /* TODO: 프로세스 종료 메시지 구현 (project2/process_termination.html 참조).
     * 자원 정리 작업은 이곳에서 구현하는 것을 권장. */

    process_cleanup ();  // 프로세스 정리 작업 수행
}

/* 현재 프로세스의 자원을 해제하는 함수. */
static void
process_cleanup (void) {
    struct thread *curr = thread_current ();  // 현재 스레드 정보

#ifdef VM
    /* 보조 페이지 테이블 제거 */
    supplemental_page_table_kill (&curr->spt);
#endif

    uint64_t *pml4;
    /* 현재 프로세스의 페이지 디렉토리를 제거하고 커널 전용 페이지 디렉토리로 전환. */
    pml4 = curr->pml4;
    if (pml4 != NULL) {
        /* 올바른 순서를 지키는 것이 중요.
         * curr->pagedir을 NULL로 설정한 후 페이지 디렉토리를 전환해야 함.
         * 그렇지 않으면 타이머 인터럽트가 발생하여 프로세스의 페이지 디렉토리로 전환할 수 있음.
         * 기본 페이지 디렉토리를 활성화한 후 프로세스의 페이지 디렉토리를 제거해야 함.
         * 그렇지 않으면 현재 활성화된 페이지 디렉토리가 제거되어(그리고 초기화되어) 문제가 발생할 수 있음. */
        curr->pml4 = NULL;
        pml4_activate (NULL);  // 기본 페이지 디렉토리로 전환
        pml4_destroy (pml4);  // 프로세스의 페이지 디렉토리 제거
    }
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
/* CPU를 새로 실행할 스레드의 사용자 코드로 설정.
 * 이 함수는 모든 컨텍스트 스위칭 시 호출된다. */
void
process_activate (struct thread *next) {
	/* 다음 스레드의 페이지 테이블을 활성화하여 사용자 주소 공간을 설정. */
	pml4_activate (next->pml4);

	/* 다음 스레드의 커널 스택을 인터럽트 처리용으로 설정. */
	tss_update (next);
}

/* ELF(Executable and Linkable Format) 바이너리를 로드하기 위한 구조체 및 상수 정의.
 * ELF는 컴파일된 실행 파일의 형식으로, 이 구조체들은 ELF 규격에서 정의된 내용들을 바탕으로 함. */

/* ELF 파일의 고유 식별자 길이 */
#define EI_NIDENT 16

/* 프로그램 헤더 타입을 정의 */
#define PT_NULL    0            /* 무시해도 되는 세그먼트 */
#define PT_LOAD    1            /* 메모리에 로드해야 하는 세그먼트 */
#define PT_DYNAMIC 2            /* 동적 링크 정보 세그먼트 */
#define PT_INTERP  3            /* 동적 로더의 이름 */
#define PT_NOTE    4            /* 보조 정보 */
#define PT_SHLIB   5            /* 예약됨 */
#define PT_PHDR    6            /* 프로그램 헤더 테이블 */
#define PT_STACK   0x6474e551   /* 스택 세그먼트 */

#define PF_X 1          /* 실행 가능한 세그먼트 */
#define PF_W 2          /* 쓰기 가능한 세그먼트 */
#define PF_R 4          /* 읽기 가능한 세그먼트 */

/* ELF 파일 헤더 구조체 정의.
 * ELF 파일의 가장 앞부분에 위치하며, 바이너리 실행 파일의 정보를 저장한다. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];  // ELF 식별자
	uint16_t e_type;                   // 파일 타입 (예: 실행 파일, 오브젝트 파일)
	uint16_t e_machine;                // CPU 아키텍처
	uint32_t e_version;                // 파일 버전
	uint64_t e_entry;                  // 프로그램의 진입점 주소
	uint64_t e_phoff;                  // 프로그램 헤더 테이블의 오프셋
	uint64_t e_shoff;                  // 섹션 헤더 테이블의 오프셋
	uint32_t e_flags;                  // 플래그
	uint16_t e_ehsize;                 // ELF 헤더의 크기
	uint16_t e_phentsize;              // 각 프로그램 헤더 엔트리의 크기
	uint16_t e_phnum;                  // 프로그램 헤더 엔트리의 개수
	uint16_t e_shentsize;              // 각 섹션 헤더 엔트리의 크기
	uint16_t e_shnum;                  // 섹션 헤더 엔트리의 개수
	uint16_t e_shstrndx;               // 섹션 헤더 문자열 테이블의 인덱스
};

/* 프로그램 헤더 구조체 정의.
 * 각 세그먼트의 정보를 저장하며, 프로그램 헤더는 ELF 파일에 여러 개 존재할 수 있다. */
struct ELF64_PHDR {
	uint32_t p_type;     // 세그먼트 타입
	uint32_t p_flags;    // 세그먼트 플래그 (읽기, 쓰기, 실행)
	uint64_t p_offset;   // 세그먼트가 파일 내에서 시작하는 오프셋
	uint64_t p_vaddr;    // 세그먼트의 메모리 가상 주소
	uint64_t p_paddr;    // 세그먼트의 물리 주소 (일반적으로 사용되지 않음)
	uint64_t p_filesz;   // 파일에 저장된 세그먼트 크기
	uint64_t p_memsz;    // 메모리에서 차지하는 세그먼트 크기
	uint64_t p_align;    // 세그먼트의 정렬 기준
};

/* 약어 정의 */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* 주어진 ELF 실행 파일을 FILE_NAME에서 현재 스레드로 로드하는 함수.
 * 실행 파일의 진입점 주소를 *RIP에 저장하고, 초기 스택 포인터를 *RSP에 저장.
 * 로드에 성공하면 true를 반환하고, 실패하면 false를 반환. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();  // 현재 스레드 포인터
	struct ELF ehdr;  // ELF 파일 헤더 구조체
	struct file *file = NULL;  // 파일 포인터 초기화
	off_t file_ofs;  // 파일 오프셋 값
	bool success = false;  // 로드 성공 여부를 저장하는 변수
	int i;

	/* 페이지 디렉터리 생성 및 활성화. 
	 * 페이지 테이블을 새롭게 생성하여 현재 스레드에 할당하고 활성화.
	 * 이 과정은 스레드가 올바른 메모리 구조를 가지고 사용자 모드에서 동작할 수 있게 한다. */
	t->pml4 = pml4_create ();  // 페이지 테이블 생성
	if (t->pml4 == NULL)  // 페이지 테이블 생성 실패 시
		goto done;  // 오류 처리
	process_activate (thread_current ());  // 현재 스레드의 페이지 테이블 활성화

	/* 실행 파일 열기.
	 * 지정된 파일 이름을 바탕으로 파일 시스템에서 실행 파일을 열고, 포인터를 반환.
	 * 파일을 열 수 없는 경우, 프로그램 로드에 실패한다. */
	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);  // 파일 열기 실패 메시지 출력
		goto done;  // 오류 처리
	}

	/* ELF 헤더를 읽고 유효성 검사 수행.
	 * 파일에서 ELF 헤더를 읽어들인 후, 해당 헤더가 올바른 형식인지 검사.
	 * 이 과정에서 파일이 실행 가능한 ELF 형식인지, 적절한 CPU 아키텍처를 사용하고 있는지 등의 체크가 포함됨. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)  // ELF 매직 넘버 체크
			|| ehdr.e_type != 2  // 실행 파일 타입 확인
			|| ehdr.e_machine != 0x3E  // CPU 아키텍처가 amd64인지 확인
			|| ehdr.e_version != 1  // ELF 버전 확인
			|| ehdr.e_phentsize != sizeof (struct Phdr)  // 프로그램 헤더 크기 확인
			|| ehdr.e_phnum > 1024) {  // 프로그램 헤더의 개수가 1024개를 초과하면 오류
		printf ("load: %s: error loading executable\n", file_name);  // 오류 메시지 출력
		goto done;  // 오류 처리
	}

	/* 프로그램 헤더 읽기.
	 * 프로그램 헤더는 실행 파일의 세그먼트 정보를 담고 있으며, 이를 바탕으로 메모리 로드 작업을 수행.
	 * 파일의 프로그램 헤더 테이블 위치에서 헤더를 읽어 들이며, 각 헤더는 세그먼트의 속성과 위치 정보를 담고 있다. */
	file_ofs = ehdr.e_phoff;  // 프로그램 헤더의 오프셋 설정
	for (i = 0; i < ehdr.e_phnum; i++) {  // 각 프로그램 헤더를 순회
		struct Phdr phdr;  // 프로그램 헤더 구조체 변수

		if (file_ofs < 0 || file_ofs > file_length (file))  // 파일 오프셋 유효성 검사
			goto done;  // 오류 처리
		file_seek (file, file_ofs);  // 파일 포인터를 해당 오프셋으로 이동

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)  // 프로그램 헤더 읽기 실패 시
			goto done;  // 오류 처리
		file_ofs += sizeof phdr;  // 다음 프로그램 헤더로 이동
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* 이 세그먼트는 무시해도 되는 타입이므로, 처리하지 않고 넘어간다. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				/* 이 세그먼트들은 로드할 수 없으므로, 로드 실패 처리 */
				goto done;
			case PT_LOAD:
				/* 로드 가능한 세그먼트인 경우, 유효성 검사 및 메모리 로드 수행 */
				if (validate_segment (&phdr, file)) {  // 세그먼트 유효성 검사
					bool writable = (phdr.p_flags & PF_W) != 0;  // 세그먼트가 쓰기 가능인지 확인
					uint64_t file_page = phdr.p_offset & ~PGMASK;  // 파일 페이지의 시작 주소 계산
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;  // 메모리 페이지의 시작 주소 계산
					uint64_t page_offset = phdr.p_vaddr & PGMASK;  // 페이지 오프셋 계산
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* 일반적인 세그먼트.
						 * 파일에서 초기 부분을 읽어 들이고 나머지 부분은 0으로 채움. */
						read_bytes = page_offset + phdr.p_filesz;  // 읽을 바이트 수 계산
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);  // 0으로 채울 바이트 수 계산
					} else {
						/* 전체가 0으로 초기화된 세그먼트.
						 * 디스크에서 아무 것도 읽지 않음. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);  // 0으로 채울 바이트 수 계산
					}
					/* 세그먼트 메모리 로드 */
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))  // 로드 실패 시
						goto done;
				}
				else
					goto done;  // 유효성 검사 실패 시 오류 처리
				break;
		}
	}

	/* 스택 설정.
	 * 프로세스 실행 시 사용할 초기 스택을 설정. */
	if (!setup_stack (if_))
		goto done;  // 스택 설정 실패 시 오류 처리

	/* 진입점 주소 설정.
	 * ELF 헤더에 정의된 진입점 주소를 설정하여, 로드된 프로세스가 해당 주소에서부터 실행되도록 한다. */
	if_->rip = ehdr.e_entry;

	/* TODO: 여기에서 명령어 인자 전달 구현 필요 (project2/argument_passing.html 참고). */

	success = true;  // 로드 성공 시 true 설정

done:
	/* 로드 성공 여부와 관계없이 파일을 닫고 자원 정리.
	 * 파일 닫기 작업은 파일 시스템의 자원 누수를 방지하기 위해 반드시 수행해야 함. */
	file_close (file);
	return success;  // 로드 성공 여부 반환
}


/* PHDR이 가리키는 세그먼트가 유효하고, 로드 가능한지 확인하는 함수.
 * 주어진 세그먼트가 파일 내의 올바른 위치에 있으며, 메모리에서의 위치가 올바른지 검증.
 * 유효하면 true를 반환하고, 그렇지 않으면 false를 반환. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset와 p_vaddr(가상 주소)의 페이지 오프셋이 동일해야 함.
	 * 이는 파일의 오프셋과 메모리의 오프셋이 일치해야 함을 의미. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset는 반드시 파일 내부의 위치를 가리켜야 함.
	 * 만약 파일의 크기보다 큰 오프셋을 가리킨다면 잘못된 세그먼트. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz(메모리 크기)는 p_filesz(파일 크기)보다 크거나 같아야 함.
	 * 메모리에서 차지할 크기가 파일에서 읽어야 할 크기보다 작다면 오류. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* 세그먼트의 메모리 크기는 0이 되어서는 안 됨. */
	if (phdr->p_memsz == 0)
		return false;

	/* 세그먼트의 가상 메모리 영역은 사용자 주소 공간 내에 있어야 함.
	 * 시작 주소와 끝 주소가 모두 사용자 메모리 영역 내에 있어야 함. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* 메모리 영역이 커널 주소 공간을 넘어가는 "랩 어라운드"가 발생해서는 안 됨.
	 * 랩 어라운드는 세그먼트가 메모리의 최대 값을 넘어 다시 0부터 시작하는 현상. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* 페이지 0을 매핑하는 것을 허용하지 않음.
	 * 페이지 0을 매핑하게 되면, null 포인터를 사용하는 사용자 코드가
	 * 시스템 콜에서 문제를 일으킬 수 있음.
	 * 예를 들어, `memcpy()` 함수에서 null 포인터로 인한 커널 패닉이 발생할 수 있음. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* 모든 조건을 통과한 경우, 세그먼트가 유효하다고 판단. */
	return true;
}

#ifndef VM
/* 이 코드는 오직 프로젝트 2에서만 사용됨.
 * 만약 프로젝트 2 전체에서 이 함수를 사용하고자 한다면,
 * #ifndef 매크로 외부에서 함수를 정의해야 함. */

/* load()를 위한 보조 함수. */
static bool install_page (void *upage, void *kpage, bool writable);

/* 파일의 오프셋 OFS에서 시작하는 세그먼트를 주소 UPAGE에 로드.
 * 총 READ_BYTES + ZERO_BYTES 바이트의 가상 메모리를 초기화.
 *
 * - UPAGE부터 시작하는 READ_BYTES 바이트는 OFS에서 FILE을 읽어야 함.
 * - UPAGE + READ_BYTES에서 시작하는 ZERO_BYTES 바이트는 0으로 채워야 함.
 *
 * 페이지가 WRITABLE로 설정된 경우 사용자 프로세스가 해당 페이지를 수정할 수 있고,
 * 그렇지 않으면 읽기 전용으로 설정됨.
 *
 * 메모리 할당 오류나 디스크 읽기 오류가 발생하면 false를 반환, 성공 시 true를 반환. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);  // 전체 바이트 수가 페이지 크기의 배수인지 확인
	ASSERT (pg_ofs (upage) == 0);  // 페이지 오프셋이 0인지 확인 (정렬)
	ASSERT (ofs % PGSIZE == 0);  // 파일 오프셋이 페이지 크기의 배수인지 확인

	file_seek (file, ofs);  // 파일의 오프셋으로 파일 포인터 이동
	while (read_bytes > 0 || zero_bytes > 0) {
		/* 이번 페이지에 읽어야 할 바이트 수를 계산.
		 * 페이지에서 FILE로부터 읽을 바이트 수와 나머지를 0으로 채울 바이트 수로 나눔. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;  // 이번에 읽을 바이트 수
		size_t page_zero_bytes = PGSIZE - page_read_bytes;  // 나머지 0으로 채울 바이트 수

		/* 메모리 페이지 할당. */
		uint8_t *kpage = palloc_get_page (PAL_USER);  // 사용자 풀에서 페이지 할당
		if (kpage == NULL)  // 페이지 할당 실패 시
			return false;

		/* 페이지에 파일 데이터를 읽어 로드. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {  // 파일 읽기 실패 시
			palloc_free_page (kpage);  // 할당된 페이지 해제
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);  // 나머지 바이트를 0으로 초기화

		/* 해당 페이지를 프로세스의 주소 공간에 추가. */
		if (!install_page (upage, kpage, writable)) {  // 페이지 추가 실패 시
			palloc_free_page (kpage);  // 할당된 페이지 해제
			return false;
		}

		/* 다음 페이지로 진행. */
		read_bytes -= page_read_bytes;  // 읽을 바이트 수 감소
		zero_bytes -= page_zero_bytes;  // 0으로 채울 바이트 수 감소
		upage += PGSIZE;  // 가상 주소를 다음 페이지로 이동
	}
	return true;  // 세그먼트 로드 성공
}

/* 사용자 스택을 초기화하여 최소한의 스택을 생성.
 * USER_STACK 위치에 0으로 채워진 페이지를 매핑. */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	/* 사용자 풀에서 0으로 초기화된 페이지를 할당. */
	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		/* 할당된 페이지를 USER_STACK의 바로 아래에 매핑하고, 성공 시 스택 포인터 설정. */
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;  // 스택 포인터 설정
		else
			palloc_free_page (kpage);  // 페이지 해제
	}
	return success;
}

/* 사용자 가상 주소 UPAGE와 커널 가상 주소 KPAGE를 페이지 테이블에 추가.
 * WRITABLE이 true이면, 사용자 프로세스가 해당 페이지를 수정할 수 있도록 설정.
 * 그렇지 않으면 읽기 전용으로 설정됨.
 * UPAGE는 이미 매핑된 주소가 아니어야 함.
 * KPAGE는 palloc_get_page()로 얻은 페이지여야 함.
 * 성공 시 true를 반환하고, UPAGE가 이미 매핑되었거나 메모리 할당 실패 시 false를 반환. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* 해당 가상 주소에 이미 페이지가 존재하지 않는지 확인하고,
	 * 페이지 테이블에 새로운 페이지를 매핑. */
	return (pml4_get_page (t->pml4, upage) == NULL  // 이미 매핑된 페이지가 없는지 확인
			&& pml4_set_page (t->pml4, upage, kpage, writable));  // 페이지 매핑 성공 여부 반환
}
#else
/* 이 코드 블록은 프로젝트 3 이후에 사용됨.
 * 만약 프로젝트 2만을 위한 함수 구현이 필요하다면,
 * 위쪽 코드 블록에서 구현. */

/* 첫 페이지 폴트가 발생했을 때, 주어진 파일에서 세그먼트를 지연 로드하는 함수. */
static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: 파일로부터 세그먼트 로드 구현.
	 * TODO: 이 함수는 해당 주소에서 첫 페이지 폴트가 발생했을 때 호출됨.
	 * TODO: VA는 이 함수를 호출할 때 사용 가능. */
}

/* 세그먼트를 로드하는 함수.
 * 세그먼트가 특정 오프셋 OFS에서 파일에 존재하며, 주소 UPAGE에 로드됨.
 * 총 READ_BYTES + ZERO_BYTES 바이트의 가상 메모리를 초기화.
 *
 * - READ_BYTES 바이트는 OFS에서 FILE을 읽어 UPAGE에 로드.
 * - UPAGE + READ_BYTES에서 시작하는 ZERO_BYTES 바이트는 0으로 초기화.
 * 성공 시 true를 반환하고, 실패 시 false를 반환. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* 이번 페이지에 읽을 바이트 수 계산 */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: lazy_load_segment로 정보를 전달하기 위해 aux 설정 */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* 다음 페이지로 이동 */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* USER_STACK에 PAGE 크기의 스택을 생성. 성공 시 true 반환. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: stack_bottom에 스택을 매핑하고, 페이지를 즉시 클레임.
	 * TODO: 성공 시, rsp를 설정.
	 * TODO: 페이지를 스택으로 표시해야 함. */
	/* TODO: 코드 작성 */

	return success;
}
#endif /* VM */
