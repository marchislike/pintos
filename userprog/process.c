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

#include "userprog/syscall.h"

#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup(void);
static bool load(const char *file_name, struct intr_frame *if_);
static void initd(void *f_name);
static void __do_fork(void *);
struct thread *get_child_process(int pid);

/* initd와 다른 프로세스를 위한 일반적인 프로세스 초기화 함수다 */
static void
process_init(void)
{
	struct thread *current = thread_current();
}

/* "initd"라는 첫 번째 사용자 프로그램을 FILE_NAME에서 로드하여 시작한다.
 * 새 스레드는 process_create_initd()가 반환되기 전에 스케줄될 수 있으며,
 * 심지어 종료될 수도 있다. initd의 스레드 ID를 반환하거나, 스레드를
 * 생성할 수 없으면 TID_ERROR를 반환한다.
 * 주의: 이 함수는 한 번만 호출되어야 한다. */
tid_t process_create_initd(const char *file_name)
{
    char *fn_copy;
    tid_t tid;

    /* FILE_NAME의 복사본을 만든다.
     * 그렇지 않으면 caller와 load() 사이에 경쟁 상태가 발생한다. */
    fn_copy = palloc_get_page(0);
    if (fn_copy == NULL)
        return TID_ERROR;
    strlcpy(fn_copy, file_name, PGSIZE);

    // Argument Passing ~
    char *save_ptr;
    strtok_r(file_name, " ", &save_ptr);
    // ~ Argument Passing

    /* FILE_NAME을 실행할 새 스레드를 만든다. */
    tid = thread_create(file_name, PRI_DEFAULT, initd, fn_copy);
    if (tid == TID_ERROR)
        palloc_free_page(fn_copy);
    return tid;
}

/* 첫 번째 사용자 프로세스를 시작하는 스레드 함수다 */
static void
initd(void *f_name)
{
#ifdef VM
	supplemental_page_table_init(&thread_current()->spt);
#endif

	process_init();

	if (process_exec(f_name) < 0)
		PANIC("initd 실행 실패하다\n");
	NOT_REACHED();
}

/* 현재 프로세스를 `name`으로 복제한다. 새 프로세스의 스레드 ID를 반환하거나,
 * 스레드를 생성할 수 없으면 TID_ERROR를 반환한다. */
tid_t process_fork(const char *name, struct intr_frame *if_ UNUSED)
{
    /* 현재 스레드를 새 스레드로 복제한다. */
    struct thread *cur = thread_current();
    memcpy(&cur->parent_if, if_, sizeof(struct intr_frame));

    /* 현재 스레드를 fork한 새 스레드를 만든다. */
    tid_t pid = thread_create(name, PRI_DEFAULT, __do_fork, cur);
    if (pid == TID_ERROR)
        return TID_ERROR;

    /* 방금 만든 새 자식 스레드를 찾아서 로드될 때까지 기다린다. */
    struct thread *child = get_child_process(pid);
    sema_down(&child->load_sema);

    /* 자식 프로세스의 pid를 반환한다. */
    return pid;
}

/* tid는 단순히 스레드의 ID일 뿐이고,
 * 실제로 해당 스레드의 데이터에 접근하려면 그 스레드의 구조체 포인터가 필요하다.
 * 그래서 get_child_process()를 통해 자식 스레드의 구조체를 찾는 과정이다 */
struct thread *get_child_process(int pid)
{
	struct thread *cur = thread_current();
	struct list *child_list = &cur->child_list;
	for (struct list_elem *e = list_begin(child_list); e != list_end(child_list); e = list_next(e))
	{
		struct thread *t = list_entry(e, struct thread, child_elem);
		if (t->tid == pid)
		{
			return t;
		}
	}
	return NULL;
}

#ifndef VM
/* 부모의 주소 공간을 pml4_for_each 함수에 전달하여 복제한다.
 * 이는 프로젝트 2에만 해당된다. */
static bool
duplicate_pte(uint64_t *pte, void *va, void *aux)
{
    struct thread *current = thread_current();
    struct thread *parent = (struct thread *)aux;
    void *parent_page;
    void *newpage;
    bool writable;

    /* 1. 만약 부모 페이지가 커널 페이지라면, 즉시 반환한다. */
    if (is_kernel_vaddr(va))
        return true;

    /* 2. 부모의 페이지 맵 레벨 4에서 VA를 해결한다. */
    parent_page = pml4_get_page(parent->pml4, va);
    if (parent_page == NULL)
        return false;

    /* 3. 자식에게 새 PAL_USER 페이지를 할당하고 결과를 NEWPAGE에 설정한다. */
    newpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (newpage == NULL)
        return false;

    /* 4. 부모 페이지를 새 페이지로 복사하고, 부모 페이지가 쓰기 가능한지 확인한다. */
    memcpy(newpage, parent_page, PGSIZE);
    writable = is_writable(pte);

    /* 5. 쓰기 가능한 권한으로 자식의 페이지 테이블에 VA에 새 페이지를 추가한다. */
    if (!pml4_set_page(current->pml4, va, newpage, writable))
    {
        /* 6. 페이지 삽입에 실패하면, 오류 처리한다. */
        return false;
    }
    return true;
}
#endif

/* 부모의 실행 컨텍스트를 복사하는 스레드 함수다
 * 힌트) parent->tf는 프로세스의 사용자 영역 컨텍스트를 포함하지 않는다.
 *       즉, process_fork의 두 번째 인자를 이 함수에 전달해야 한다. */
static void
__do_fork(void *aux)
{
    struct intr_frame if_;
    struct thread *parent = (struct thread *)aux;
    struct thread *current = thread_current();
    struct intr_frame *parent_if = &parent->parent_if;
    bool succ = true;

    /* 1. CPU 컨텍스트를 로컬 스택으로 읽어온다. */
    memcpy(&if_, parent_if, sizeof(struct intr_frame));
    if_.R.rax = 0; // 자식 프로세스의 리턴값은 0이다

    /* 2. 페이지 테이블을 복제한다 */
    current->pml4 = pml4_create();
    if (current->pml4 == NULL)
        goto error;

    process_activate(current);
#ifdef VM
    supplemental_page_table_init(&current->spt);
    if (!supplemental_page_table_copy(&current->spt, &parent->spt))
        goto error;
#else
    if (!pml4_for_each(parent->pml4, duplicate_pte, parent))
        goto error;
#endif

    /* 여기에 코드를 추가한다.
     * 힌트) 파일 객체를 복제하려면 include/filesys/file.h의 `file_duplicate`를 사용한다.
     *      부모가 fork()에서 반환되기 전에 이 함수가 부모의 자원을 성공적으로 복제해야 한다.*/

    // FDT 복사
    for (int i = 0; i < FDT_COUNT_LIMIT; i++)
    {
        struct file *file = parent->fdt[i];
        if (file == NULL)
            continue;
        if (file > 2)
            file = file_duplicate(file);
        current->fdt[i] = file;
    }
    current->next_fd = parent->next_fd;

    // 로드가 완료될 때까지 기다리고 있던 부모의 대기를 해제한다
    sema_up(&current->load_sema);
    process_init();

    /* 마침내 새로 생성된 프로세스로 전환한다. */
    if (succ)
        do_iret(&if_);
error:
    sema_up(&current->load_sema);
    exit(TID_ERROR);
}

/* f_name으로 현재 실행 컨텍스트를 전환한다.
 * 실패 시 -1을 반환한다. */
int process_exec(void *f_name)
{
    char *file_name = f_name;
    bool success;

    /* 현재 스레드의 intr_frame을 사용할 수 없다. 
     * 현재 스레드가 다시 스케줄될 때, 실행 정보를 저장하기 때문이다. */
    struct intr_frame _if;
    _if.ds = _if.es = _if.ss = SEL_UDSEG;
    _if.cs = SEL_UCSEG;
    _if.eflags = FLAG_IF | FLAG_MBS;

    /* 현재 컨텍스트를 종료한다. */
    process_cleanup();

    // Argument Passing ~
    char *parse[64];
    char *token, *save_ptr;
    int count = 0;
    for (token = strtok_r(file_name, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr))
        parse[count++] = token;
    // ~ Argument Passing

    /* 바이너리 파일을 로드한다. */
    lock_acquire(&filesys_lock);
    success = load(file_name, &_if);
    lock_release(&filesys_lock);
    // 로드 후 실행 시작 주소와 스택 포인터 초기화한다.

    // Argument Passing ~
    argument_stack(parse, count, &_if.rsp); // 함수 내부에서 parse와 rsp 값을 직접 변경하기 위해 주소 전달
    _if.R.rdi = count;
    _if.R.rsi = (char *)_if.rsp + 8;
    // ~ Argument Passing

    /* 로드 실패하면 종료한다. */
    palloc_free_page(file_name);
    if (!success)
        return -1;

    /* 시작된 프로세스로 전환한다. */
    do_iret(&_if);
    NOT_REACHED();
}

void argument_stack(char **parse, int count, void **rsp) // 주소를 전달받았으므로 이중 포인터 사용한다
{
    // 프로그램 이름과 인자 문자열을 스택에 넣는다.
    for (int i = count - 1; i > -1; i--)
    {
        for (int j = strlen(parse[i]); j > -1; j--)
        {
            (*rsp)--;                      // 스택 주소 감소한다
            **(char **)rsp = parse[i][j]; // 문자 저장한다
        }
        parse[i] = *(char **)rsp; // 이 주소 저장해두면 인자가 시작하는 곳을 알 수 있다
    }

    // 정렬 패딩 넣는다
    int padding = (int)*rsp % 8;
    for (int i = 0; i < padding; i++)
    {
        (*rsp)--;
        **(uint8_t **)rsp = 0; // 패딩 채운다
    }

    // 인자 문자열 끝나는 거 표시하는 0 넣는다
    (*rsp) -= 8;
    **(char ***)rsp = 0;

    // 각 인자 시작 주소 넣는다
    for (int i = count - 1; i > -1; i--)
    {
        (*rsp) -= 8;
        **(char ***)rsp = parse[i];
    }

    // 리턴 주소 넣는다
    (*rsp) -= 8;
    **(void ***)rsp = 0;
}

/* 스레드 TID가 종료될 때까지 기다린 후 그 종료 상태를 반환한다.
 * 커널에 의해 종료된 경우(예: 예외로 인해 종료됨), -1을 반환한다.
 * TID가 유효하지 않거나 호출 프로세스의 자식이 아닌 경우,
 * 또는 이미 주어진 TID에 대해 process_wait()이 성공적으로 호출된 경우,
 * 기다리지 않고 즉시 -1을 반환한다.
 *
 * 이 함수는 문제 2-2에서 구현될 것이다. 현재는 아무 것도 하지 않는다. */
int process_wait(tid_t child_tid UNUSED)
{
    struct thread *child = get_child_process(child_tid);
    if (child == NULL)
        return -1;

    sema_down(&child->wait_sema);
    list_remove(&child->child_elem);
    sema_up(&child->exit_sema);
    return child->exit_status;
}

/* Exit the process. This function is called by thread_exit(). */
void process_exit(void)
{
    struct thread *cur = thread_current();

    // 1) FDT의 모든 파일을 닫고 메모리를 반환한다.
    for (int i = 2; i < FDT_COUNT_LIMIT; i++)
        close(i);
    palloc_free_page(cur->fdt);
    
    file_close(cur->running); // 2) 현재 실행 중인 파일도 닫는다.
    process_cleanup();

    // 3) 자식이 종료될 때까지 대기하고 있는 부모에게 신호를 보낸다.
    sema_up(&cur->wait_sema);
    // 4) 부모의 신호를 기다린다. 대기가 풀리고 나서 do_schedule(THREAD_DYING)이 이어져 다른 스레드가 실행된다.
    sema_down(&cur->exit_sema);
}

/* 현재 프로세스의 자원을 해제한다. */
static void
process_cleanup(void)
{
    struct thread *curr = thread_current();

#ifdef VM
    supplemental_page_table_kill(&curr->spt);
#endif

    uint64_t *pml4;
    /* 현재 프로세스의 페이지 디렉토리를 삭제하고 커널 전용 페이지 디렉토리로 전환한다. */
    pml4 = curr->pml4;
    if (pml4 != NULL)
    {
        /* 여기에서 올바른 순서가 중요하다. cur->pagedir을 NULL로 설정한 후에
         * 페이지 디렉토리를 전환해야 타이머 인터럽트가 프로세스 페이지 디렉토리로 전환하지 않는다.
         * 기본 페이지 디렉토리를 활성화한 후에 프로세스의 페이지 디렉토리를 삭제해야 하며,
         * 그렇지 않으면 활성 페이지 디렉토리가 해제된 페이지 디렉토리가 된다. */
        curr->pml4 = NULL;
        pml4_activate(NULL);
        pml4_destroy(pml4);
    }
}

/* 다음 스레드에서 사용자 코드를 실행하기 위해 CPU를 설정한다.
 * 이 함수는 매 컨텍스트 전환 시 호출된다. */
void process_activate(struct thread *next)
{
    /* 스레드의 페이지 테이블을 활성화한다. */
    pml4_activate(next->pml4);

    /* 인터럽트 처리를 위해 스레드의 커널 스택을 설정한다. */
    tss_update(next);
}

/* 우리는 ELF 바이너리를 로드한다. 다음 정의는 ELF 사양([ELF1])에서 가져온 것이다. */

/* ELF 타입. [ELF1] 1-2 참조. */
#define EI_NIDENT 16

#define PT_NULL 0			/* 무시한다. */
#define PT_LOAD 1			/* 로드 가능한 세그먼트다. */
#define PT_DYNAMIC 2		/* 동적 링크 정보다. */
#define PT_INTERP 3			/* 동적 로더의 이름이다. */
#define PT_NOTE 4			/* 보조 정보다. */
#define PT_SHLIB 5			/* 예약되었다. */
#define PT_PHDR 6			/* 프로그램 헤더 테이블이다. */
#define PT_STACK 0x6474e551 /* 스택 세그먼트다. */

#define PF_X 1 /* 실행 가능하다. */
#define PF_W 2 /* 쓰기 가능하다. */
#define PF_R 4 /* 읽기 가능하다. */

/* 실행 가능한 헤더. [ELF1] 1-4부터 1-8 참조.
 * 이는 ELF 바이너리의 맨 앞에 나타난다. */
struct ELF64_hdr
{
    unsigned char e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};
/* ELF 프로그램 헤더 구조체다 */
struct ELF64_PHDR
{
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

/* FILE_NAME에서 ELF 실행 파일을 현재 스레드로 로드한다.
 * 실행 파일의 진입 지점을 *RIP에 저장하고
 * 초기 스택 포인터를 *RSP에 저장한다.
 * 성공 시 true를 반환하고, 실패 시 false를 반환한다. */
static bool
load(const char *file_name, struct intr_frame *if_)
{
    struct thread *t = thread_current();
    struct ELF ehdr;
    struct file *file = NULL;
    off_t file_ofs;
    bool success = false;
    int i;

    /* 페이지 디렉토리를 할당하고 활성화한다. */
    t->pml4 = pml4_create(); // 페이지 dir(페이지 테이블 포인터) 생성
    if (t->pml4 == NULL)
        goto done;
    process_activate(thread_current()); // 이 함수 안에서 페이지 테이블 활성화함

    /* 실행 파일을 연다. */
    file = filesys_open(file_name);
    if (file == NULL)
    {
        printf("load: %s: open failed\n", file_name);
        goto done;
    }

    /* 실행 헤더를 읽고 검증한다. */
    if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 0x3E // amd64
        || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) || ehdr.e_phnum > 1024)
    {
        printf("load: %s: error loading executable\n", file_name);
        goto done;
    }

    /* 프로그램 헤더들을 읽는다. */
    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++)
    {
        struct Phdr phdr;

        if (file_ofs < 0 || file_ofs > file_length(file))
            goto done;
        file_seek(file, file_ofs);

        if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
            goto done;
        file_ofs += sizeof phdr;
        switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
            /* 이 세그먼트를 무시한다. */
            break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
            goto done;
        case PT_LOAD:
            if (validate_segment(&phdr, file))
            {
                bool writable = (phdr.p_flags & PF_W) != 0;
                uint64_t file_page = phdr.p_offset & ~PGMASK;
                uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
                uint64_t page_offset = phdr.p_vaddr & PGMASK;
                uint32_t read_bytes, zero_bytes;
                if (phdr.p_filesz > 0)
                {
                    /* 일반 세그먼트다. 디스크에서 초기 부분을 읽고 나머지는 0으로 채운다. */
                    read_bytes = page_offset + phdr.p_filesz;
                    zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
                }
                else
                {
                    /* 전체를 0으로 채운다. 디스크에서 읽지 않는다. */
                    read_bytes = 0;
                    zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
                }
                if (!load_segment(file, file_page, (void *)mem_page,
                                  read_bytes, zero_bytes, writable))
                    goto done;
            }
            else
                goto done;
            break;
        }
    }

    // 스레드가 삭제될 때 파일을 닫을 수 있게 파일을 구조체에 저장한다.
    t->running = file;
    // 현재 실행 중인 파일은 수정할 수 없게 막는다.
    file_deny_write(file);
    /* 스택을 설정한다. */
    if (!setup_stack(if_)) // user stack 초기화
        goto done;

    /* 시작 주소를 설정한다. */
    if_->rip = ehdr.e_entry; // entry point 초기화
    // rip: 프로그램 카운터(실행할 다음 인스트럭션의 메모리 주소)

    /* 여기에 코드를 추가한다.
     * 힌트) 인자 전달을 구현하라(참조: project2/argument_passing.html). */

    success = true;

done:
    /* 성공 여부에 관계없이 여기에 도달한다. */
    // 파일을 여기서 닫지 않고 스레드가 삭제될 때 process_exit에서 닫는다.
    // file_close(file);
    return success;
}

/* PHDR가 파일에서 유효하고 로드 가능한 세그먼트를 설명하면 true를 반환하고, 그렇지 않으면 false를 반환한다. */
static bool
validate_segment(const struct Phdr *phdr, struct file *file)
{
    /* p_offset과 p_vaddr는 같은 페이지 오프셋을 가져야 한다. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
        return false;

    /* p_offset은 파일 내에 있어야 한다. */
    if (phdr->p_offset > (uint64_t)file_length(file))
        return false;

    /* p_memsz는 p_filesz보다 크거나 같아야 한다. */
    if (phdr->p_memsz < phdr->p_filesz)
        return false;

    /* 세그먼트는 비어 있지 않아야 한다. */
    if (phdr->p_memsz == 0)
        return false;

    /* 가상 메모리 영역은 사용자 주소 공간 범위 내에서 시작하고 끝나야 한다. */
    if (!is_user_vaddr((void *)phdr->p_vaddr))
        return false;
    if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
        return false;

    /* 영역은 커널 가상 주소 공간을 가로질러 "wrap around"할 수 없다. */
    if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
        return false;

    /* 페이지 0을 매핑하는 것은 금지된다.
       페이지 0을 매핑하는 것은 나쁜 생각일 뿐만 아니라,
       그것을 허용한다면 시스템 호출에 null 포인터를 전달한 사용자 코드가
       memcpy() 등에서 null 포인터 단언으로 커널을 패닉시킬 가능성이 매우 높다. */
    if (phdr->p_vaddr < PGSIZE)
        return false;

    /* 괜찮다. */
    return true;
}

int process_add_file(struct file *f)
{
    struct thread *curr = thread_current();
    struct file **fdt = curr->fdt;

    // limit을 넘지 않는 범위 안에서 빈 자리를 탐색한다
    while (curr->next_fd < FDT_COUNT_LIMIT && fdt[curr->next_fd])
        curr->next_fd++;
    if (curr->next_fd >= FDT_COUNT_LIMIT)
        return -1;
    fdt[curr->next_fd] = f;

    return curr->next_fd;
}

struct file *process_get_file(int fd)
{
    struct thread *curr = thread_current();
    struct file **fdt = curr->fdt;
    /* 파일 디스크립터에 해당하는 파일 객체를 반환한다 */
    /* 없을 시 NULL을 반환한다 */
    if (fd < 2 || fd >= FDT_COUNT_LIMIT)
        return NULL;
    return fdt[fd];
}

void process_close_file(int fd)
{
    struct thread *curr = thread_current();
    struct file **fdt = curr->fdt;
    if (fd < 2 || fd >= FDT_COUNT_LIMIT)
        return;
    fdt[fd] = NULL;
}

#ifndef VM
/* 이 블록의 코드는 프로젝트 2에서만 사용된다.
 * 프로젝트 2 전반에 걸쳐 함수를 구현하려면 #ifndef 매크로 외부에서 구현하라. */

/* load() 도우미 함수다. */
static bool install_page(void *upage, void *kpage, bool writable);
/* FILE에서 OFS 오프셋에서 시작하는 세그먼트를 주소 UPAGE에 로드한다.
 * 총 READ_BYTES + ZERO_BYTES 바이트의 가상 메모리가 초기화된다:
 *
 * - READ_BYTES 바이트는 FILE에서 OFS에서 시작하여 UPAGE에 읽어야 한다.
 *
 * - READ_BYTES 뒤에 있는 UPAGE + ZERO_BYTES 바이트는 0으로 채워야 한다.
 *
 * 이 함수로 초기화된 페이지는 WRITABLE이 true일 경우 사용자 프로세스가 수정할 수 있고,
 * 그렇지 않은 경우 읽기 전용이다.
 *
 * 성공 시 true를 반환하고, 메모리 할당 오류나 디스크 읽기 오류가 발생하면 false를 반환한다. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
             uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    file_seek(file, ofs);
    while (read_bytes > 0 or zero_bytes > 0)
    {
        /* 이 페이지를 채우는 방법을 계산한다.
         * FILE에서 PAGE_READ_BYTES 바이트를 읽고
         * 마지막 PAGE_ZERO_BYTES 바이트를 0으로 채운다. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* 메모리 페이지를 가져온다. */
        uint8_t *kpage = palloc_get_page(PAL_USER);
        if (kpage == NULL)
            return false;

        /* 이 페이지를 로드한다. */
        if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes)
        {
            palloc_free_page(kpage);
            return false;
        }
        memset(kpage + page_read_bytes, 0, page_zero_bytes);

        /* 프로세스의 주소 공간에 페이지를 추가한다. */
        if (!install_page(upage, kpage, writable))
        {
            printf("fail\n");
            palloc_free_page(kpage);
            return false;
        }

        /* 다음으로 진행한다. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }
    return true;
}

/* USER_STACK에 0으로 채워진 페이지를 매핑하여 최소한의 스택을 만든다. */
static bool
setup_stack(struct intr_frame *if_)
{
    uint8_t *kpage;
    bool success = false;

    kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kpage != NULL)
    {
        success = install_page(((uint8_t *)USER_STACK) - PGSIZE, kpage, true);
        if (success)
            if_->rsp = USER_STACK;
        else
            palloc_free_page(kpage);
    }
    return success;
}

/* 사용자 가상 주소 UPAGE에서 커널 가상 주소 KPAGE로의 매핑을 페이지 테이블에 추가한다.
 * WRITABLE이 true일 경우, 사용자 프로세스가 페이지를 수정할 수 있고,
 * 그렇지 않으면 읽기 전용이다.
 * UPAGE는 이미 매핑되어 있으면 안 된다.
 * KPAGE는 palloc_get_page()로 사용자 풀에서 얻은 페이지여야 한다.
 * 성공 시 true를 반환하고, UPAGE가 이미 매핑되어 있거나 메모리 할당이 실패한 경우 false를 반환한다. */
static bool
install_page(void *upage, void *kpage, bool writable)
{
    struct thread *t = thread_current();

    /* 해당 가상 주소에 이미 페이지가 없는지 확인한 후, 페이지를 매핑한다. */
    return (pml4_get_page(t->pml4, upage) == NULL && pml4_set_page(t->pml4, upage, kpage, writable));
}

#else
/* 여기서부터의 코드는 프로젝트 3 이후에 사용된다.
 * 프로젝트 2만을 위해 함수를 구현하려면,
 * 상단 블록 외부에서 구현하라. */

static bool
lazy_load_segment(struct page *page, void *aux)
{
    /* TODO: 파일에서 세그먼트를 로드한다 */
    /* TODO: 이 함수는 주소 VA에서 첫 페이지 결함이 발생할 때 호출된다. */
    /* TODO: 이 함수를 호출할 때 VA는 사용 가능하다. */
}

/* 파일에서 시작 오프셋 OFS와 주소 UPAGE에서 세그먼트를 로드한다.
 * 총 READ_BYTES + ZERO_BYTES 바이트의 가상 메모리가 초기화되는데, 다음과 같다:
 *
 * - READ_BYTES 바이트는 OFS에서 시작하여 FILE에서 UPAGE로 읽어야 한다.
 *
 * - ZERO_BYTES 바이트는 UPAGE + READ_BYTES에서 0으로 채워야 한다.
 *
 * 이 함수로 초기화된 페이지는 WRITABLE이 true일 경우 사용자 프로세스에 의해 쓰기 가능해야 하고, 그렇지 않으면 읽기 전용이다.
 *
 * 메모리 할당 오류나 디스크 읽기 오류가 발생하면 false를 반환하고, 성공하면 true를 반환한다. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
             uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    while (read_bytes > 0 || zero_bytes > 0)
    {
        /* 이 페이지를 채우는 방법을 계산한다.
         * 파일에서 PAGE_READ_BYTES 바이트를 읽고
         * 마지막 PAGE_ZERO_BYTES 바이트를 0으로 채운다. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* TODO: lazy_load_segment에 정보를 전달하기 위해 aux를 설정한다. */
        void *aux = NULL;
        if (!vm_alloc_page_with_initializer(VM_ANON, upage,
                                            writable, lazy_load_segment, aux))
            return false;

        /* 진행한다. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }
    return true;
}

/* USER_STACK에서 페이지를 만들어 성공하면 true를 반환한다. */
static bool
setup_stack(struct intr_frame *if_)
{
    bool success = false;
    void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

    /* TODO: 스택을 stack_bottom에 매핑하고 페이지를 즉시 요구한다.
     * TODO: 성공하면 rsp를 accordingly 설정한다.
     * TODO: 페이지가 스택임을 표시해야 한다. */
    /* TODO: 여기에 코드를 작성한다 */

    return success;
}
#endif /* VM */
