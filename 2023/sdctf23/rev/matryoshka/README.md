# San Diego CTF 2023 `Galactic Matryoshka [rev]` writeup

## 問題
This virtual Matryoshka doll is bigger than the size of the observable universe! Good luck finding the flag inside.

バイナリファイルが提供される。

## 解法
とりあえず実行してみる。
すると"doll-1"というバイナリが生成された。
"doll-1"を実行すると、今度は"doll-2"が生成された。

なるほど、確かにマトリョーシカだ。
最終層に到達するまで待ってたら日が暮れそうなのでghidraに食わせることに。

```c
undefined8 FUN_001018e1(void)

{
  undefined8 uVar1;
  undefined8 uVar2;
  long in_FS_OFFSET;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  long local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (DAT_00104038 == 0x73b8e98d1b3879a2) {
    FUN_00101830();
  }
  else {
    printf("Unwrapping the %llu-th doll\n",DAT_00104038 + 1);
    local_38 = DAT_00104020;
    local_30 = DAT_00104028;
    local_28 = DAT_00104030;
    local_20 = DAT_00104038;
    uVar1 = FUN_00101309();
    local_28 = FUN_00101373(DAT_00104030,uVar1);
    uVar2 = FUN_00101373(local_30,0xb);
    local_30 = FUN_00101373(uVar2,uVar1);
    local_20 = local_20 + 1;
    FUN_00101645(&local_38);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

基本的には、グローバル変数をローカル変数に読み出して`FUN_00101373`で更新する、`FUN_00101645`が更新した値をグローバル変数に書き込んだうえで自分自身のコピーを生成するという流れ。

0x73b8e98d1b3879a2個目のバイナリを実行するとフラグが出るらしい。
どだい不可能なので仕方なく`FUN_00101373`の動作を追うことに。

```c
long FUN_00101373(long param_1,long param_2)

{
  ulong uVar1;
  long lVar2;
  long local_28;
  int local_14;
  long local_10;
  
  local_10 = 0;
  local_28 = param_2;
  for (local_14 = 0; local_14 < 0x40; local_14 = local_14 + 1) {
    uVar1 = local_10 * 2;
    lVar2 = SUB168(ZEXT816(uVar1) * ZEXT816(0x23b3) >> 0x40,0);
    local_10 = uVar1 + ((uVar1 - lVar2 >> 1) + lVar2 >> 0x3e) * -0x7fffffffffffee27;
    if (local_28 < 0) {
      uVar1 = local_10 + param_1;
      lVar2 = SUB168(ZEXT816(uVar1) * ZEXT816(0x23b3) >> 0x40,0);
      local_10 = uVar1 + ((uVar1 - lVar2 >> 1) + lVar2 >> 0x3e) * -0x7fffffffffffee27;
    }
    local_28 = local_28 << 1;
  }
  return local_10;
}
```

分からん。
ので、`param_1`と`param_2`に適当な値を入れてgdbで動的解析することに。

すると、ややこしいことやってるようで実は乗算計算っぽいことが分かった。
(ghidraのコード見たら確かに`param_2`のbitが立ったときに足し算してる)

ただ、小さい数字を入れたときは普通の乗算なのだが、乗算結果が8バイトを超えるような大きい数字を入れると結果が一定数ずれる。
多分modを取ってるんだろうとguessしてpythonの計算結果と比較する。
正解だった様子。
ghidraのコードにもある0x7fffffffffffee27という数字が合同式の法だった。

ソースコードを少し書き直してみる。(DAT_00104020は新しいバイナリ生成するときしか使わないうえに更新されないから無視)

```c
undefined8 DAT_00104020 = 0x5999ffae750b4af1;
uint64_t x = 1;
uint64_t y = 1;
uint64_t cnt = 0;


undefined8 main(){
  uint64_t r;
  uint64_t tmp;
  uint64_t fs;
  undefined8 local_38;
  uint64_t local_x;
  uint64_t local_y;
  uint64_t local_cnt;

  if (cnt == 0x73b8e98d1b3879a2) {
    show_flag();
  }
  else {
    printf("Unwrapping the %llu-th doll\n",cnt + 1);
    local_38 = DAT_00104020;
    local_x = x;
    local_y = y;
    local_cnt = cnt;
    r = random();
    local_y = mul(y,r);
    tmp = mul(local_x,11);
    local_x = mul(tmp,r);
    local_cnt++;
    create_doll(&local_38);
  }
  return 0;
}
```

実行の度に`y`は乱数`r`と、`x`は11それから`r`と乗算される。
`r`を当てることはできないが、`show_flag()`の中で消えてくれるだろうと期待して関数を見に行く。
予想通り、関数の中で`x * y ^ {-1}`していたので乱数は相殺された。

```c
void show_flag(){
  undefined8 uVar1;
  undefined8 local_19;
  
  uVar1 = inv(y);
  uVar1 = mul(x,uVar1);
  local_19 = mul(0x888be665bfb73f2,uVar1);
  puts("Congrats! You found the flag:");
  printf("sdctf{%s_%llu}\n",&local_19,uVar1);
  return;
}
```

(`inv`関数の解析は省略)

最終的に必要なのは`11^{0x73b8e98d1b3879a2} (mod 0x7fffffffffffee27)`と`0x888be665bfb73f2 * 11^{0x73b8e98d1b3879a2} (mod 0x7fffffffffffee27)`だと判明する。
これらはPythonで高速に計算できる。

```py
from pwn import *

M = 0x7fffffffffffee27
loop = 0x73b8e98d1b3879a2

d = pow(11, loop, M)
s = p64(0x888be665bfb73f2 * d % M).decode()

print(f'FLAG is sdctf{{{s}_{d}}}')
```

FLAG: `sdctf{sQU&Mu1t_3865704192625469676}`