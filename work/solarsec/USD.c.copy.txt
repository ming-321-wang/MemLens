#include<stdio.h>
#include<stdlib.h>
#include<sys/ptrace.h>
#include<sys/wait.h>
#include<errno.h>
typedef unsigned char BYTE;
typedef unsigned long DWORD;
typedef unsigned long long DWORD64;
typedef struct
{
	DWORD64 start;
	DWORD64 end;
} seg_info;
int parse_seg_info(pid_t pid, seg_info** segs, DWORD* cnt)
{
	*cnt = 0;
	*segs = malloc(128 * sizeof(seg_info));
	char path[256] = { 0 };
	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	FILE* fp = fopen(path, "r");
	if (!fp)
	{
		free(*segs);
		*segs = 0;
		return 0;
	}
	char line[256] = { 0 };
	while (fgets(line, sizeof(line), fp))
	{
		seg_info* seg = &(*segs)[*cnt];
		if (sscanf(line, "%llx-%llx", &seg->start, &seg->end) != 2)
		{
			free(*segs);
			*segs = 0;
			*cnt = 0;
			fclose(fp);
			return 0;
		}
		(*cnt)++;
	}
	fclose(fp);
	return 1;
}
int read_sec(pid_t pid, void* dst, DWORD64 src, size_t size)
{
	size_t i;
	BYTE* p = (BYTE*)dst;
	for (i = 0; i < size; i += sizeof(DWORD64))
	{
		DWORD64 ret = ptrace(PTRACE_PEEKTEXT, pid, (void*)(src + i), NULL);
		if (ret == -1 && errno)
		{
			return 0;
		}
		*(DWORD64*)(p + i) = ret;
	}
	return 1;
}
int dump_sec(pid_t pid, seg_info* seg)
{
	size_t size = seg->end - seg->start;
	void* buff = malloc(size);
	if (!buff)
	{
		return 0;
	}
	if (!read_sec(pid, buff, seg->start, size))
	{
		free(buff);
		return 0;
	}
	char filename[256] = { 0 };
	snprintf(filename, sizeof(filename), "dumped_%d_[%llx-%llx].bin", pid, seg->start, seg->end);
	FILE* fp = fopen(filename, "wb");
	if (!fp)
	{
		free(buff);
		return 0;
	}
	fwrite(buff, 1, size, fp);
	free(buff);
	fclose(fp);
	printf("dumped to file %s!\n", filename);
	return 1;
}
int main(int argc, char* argv[])
{
	printf("Ultimate Segment Dumper V1.0 by Solarsec.\n");
	if (argc != 2)
	{
		printf("usage: %s <pid>\n", argv[0]);
		return 0;
	}
	pid_t pid = atoi(argv[1]);
	seg_info* segs = NULL;
	DWORD seg_cnt = 0;
	if (!parse_seg_info(pid, &segs, &seg_cnt))
	{
		return 0;
	}
	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
	{
		free(segs);
		return 0;
	}
	int stat;
	waitpid(pid, &stat, 0);
	for (int i = 0; i < seg_cnt; i++)
	{
		if (!dump_sec(pid, &segs[i]))
		{
			break;
		}
	}
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
	free(segs);
	return 1;
}