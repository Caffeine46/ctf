struct person{
    char first[8];
    char middle[8];
    char last[8];
    int age;
    char bio[0x100];
};

struct paper{
    struct person *ptr;
    unsigned int size;
};

struct paper memo[16];

void add(){
    byte bVar1;
    void *p;
    byte idx;
    unsigned int s;

    puts("Enter index: ");
    __isoc99_scanf("%hhu", &idx);
    puts("Enter size (1032 minimum): ");
    __isoc99_scanf("%lu", &s);
    bVar1 = idx;
    if (((idx < 15) && (1031 < s)) && (memo[idx].size == NULL)) {
        p = malloc(s);
        memo[idx].ptr = p;
        memo[idx].size = s;
        puts("Successfuly added!");
        puts("Input firstname: ");
        read(0, memo[idx].ptr->fisrt , 8);
        puts("Input middlename: ");
        read(0, memo[idx].ptr->midlle, 8);
        puts("Input lastname: ");
        read(0, memo[idx].ptr->last, 8);
        puts("Input age: ");
        __isoc99_scanf("%lu", memo[idx].ptr->age);
        puts("Input bio: ");
        read(0, memo[idx].ptr->bio, 256);
    }
    else puts("Error with either index or size...");
    return;
}

void show(){
    byte idx;
    
    puts("Enter index: ");
    __isoc99_scanf("%hhu", &idx);
    if ((idx < 15) && (memo[idx].size != 0)) {
        printf("Name\n last: %s first: %s middle: %s age: %d\nbio: %s", memo[idx].ptr->last, memo[idx].ptr->fisrt, memo[idx].ptr->middle, memo[idx].ptr->age, memo[idx].ptr->bio);
    }
    else puts("Invalid index");
    return;
}

void delete(){
    byte idx;

    printf("Enter index: ");
    __isoc99_scanf("%hhu", &idx);
    if ((idx < 15) && (memo[idx].size != 0)) {
        free(memo[idx].ptr);
        memo[idx].size = 0;
        puts("Successfully Deleted!");
    }
    else puts("Either index error or trying to delete something you shouldn\'t be...");
    return;
}

void edit(){
    byte idx;

    printf("Enter index: ");
    __isoc99_scanf("%hhu", &idx);
    if ((idx < 15) && (memo[idx].size != 0)) {
        puts("Input firstname: ");
        read(0, memo[idx].ptr->fisrt , 8);
        puts("Input middlename: ");
        read(0, memo[idx].ptr->midlle, 8);
        puts("Input lastname: ");
        read(0, memo[idx].ptr->last, 8);
        puts("Input age: ");
        __isoc99_scanf("%lu", memo[idx].ptr->age);
        printf("Input bio: (max %d)\n", memo[idx].size - 32);
        read(0, memo[idx].ptr->bio, memo[idx].size - 32);
        puts("Successfully edit\'d!");
    }
    return;
}

void re_age(){
    byte idx;

    printf("Index: ");
    __isoc99_scanf("%hhu", &idx);
    if (idx < 15) {
        printf("new age: ");
        __isoc99_scanf("%lu", memo[age].ptr->age);
        puts("Successfully re-aged!");
    }
    else puts("Invalid index...");
    return;
}

int main(){
    long input;
    code *func_table[5];
    
    setvbuf(stdin,NULL,2,0);
    setvbuf(stdout,NULL,2,0);
    setvbuf(stderr,NULL,2,0);
    func_table[0] = add;
    func_table[1] = show;
    func_table[2] = delete;
    func_table[3] = edit;
    func_table[4] = re_age;
    puts("  ____     _          _ _   ____");
    puts(" / ___|___| |__   ___| | | |___ \\ ");
    puts("| |   / __| \'_ \\ / _ \\ | |   __) |");
    puts("| |___\\__ \\ | | |  __/ | |  / __/ ");
    puts(" \\____|___/_| |_|\\___|_|_| |_____|");
    puts("");
    puts("       /\\");
    puts("      {.-}");
    puts("     ;_.-\'\\");
    puts("    {    _.}_");
    puts("    \\.-\' /  `,");
    puts("     \\  |    /");
    puts("      \\ |  ,/");
    puts("       \\|_/");
    puts("");
    do {
        while( true ){
            puts("1 Add");
            puts("2 Show");
            puts("3 delete");
            puts("4 edit");
            puts("5 re-age user");
            __isoc99_scanf("%li",&input);
            if (5 < input) break;
            (*func_table[input + -1])();
        }
        puts("Invalid Choice!");
    } while( true );
}