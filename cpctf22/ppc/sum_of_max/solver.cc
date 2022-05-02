#include <bits/stdc++.h>
#define rep(i, n) for (int i = 0; i < (int)(n); i++)
#define rep2(i, j, k) for(int i = j; i < k; i++)
#define print(x) cout << x
#define printfloat(x,y) cout << std::fixed << std::setprecision(y) << x << endl
#define newline cout << endl
#define space cout << ' '
#define INF 1000000007
#define pie 3.14159265358979
using namespace std;
using ll = long long;
using vi = vector<int>;
using vl = vector<ll>;
using vvi = vector<vector<int>>;
using vvl = vector<vector<ll>>;
using vii = vector<pair<int,int>>;
using vli = vector<pair<ll,int>>;
using pi = pair<int,int>;
using ppi = pair<pi,int>;

// M: 剰余系の法
// modpow(a,n): a^n (mod M) を二分累乗法で計算 O(log n)
// modinv(a): Mを法とする剰余系におけるaの逆元をフェルマーの小定理から計算 O(log M) (Mが素数であることが必要)
// MAX: 階乗，逆元，階乗の逆元をテーブル化したものをどこまで作るか
// fac[i]: i! (mod M)
// inv[i]: iの逆元 (mod M)
// finv[i]: i!の逆元 (mod M)
// COMinit(): 階乗，逆元，階乗の逆元をテーブル化する関数 O(MAX)
// COM(n,k): 二項係数 nCk (mod M)を計算 O(1)
ll M = 998244353;

long long modpow(long long a, long long n) {
    long long p = 1, q = a % M;
    while(n > 0){
        if(n & 1) { p *= q; p %= M; }
        q *= q; q %= M;
        n >>= 1;
    }
    return p;
}

long long modinv(long long a) {
    return modpow(a, M - 2);
}

const int MAX = 200001;
long long fac[MAX], finv[MAX], inv[MAX];

void COMinit() {
    fac[0] = fac[1] = 1;
    finv[0] = finv[1] = 1;
    inv[1] = 1;
    for(int i = 2; i < MAX; i++){
        fac[i] = fac[i - 1] * i % M;
        inv[i] = M - inv[M%i] * (M / i) % M;
        finv[i] = finv[i - 1] * inv[i] % M;
    }
}

long long COM(int n, int k){
    if (n < k) return 0;
    if (n < 0 || k < 0) return 0;
    return fac[n] * (finv[k] * finv[n - k] % M) % M;
}

int main(){
    ll n,k;
    cin >>n>>k;
    vl a(n);
    rep(i,n) cin >>a[i];
    COMinit();
    sort(a.begin(),a.end(),greater<ll>());
    ll ans = 0;
    rep(i,n){
        if(n-i == k-1) break;
        ll tmp = a[i];
        tmp *= COM(n-1-i,k-1);
        tmp %= M;
        ans += tmp;
        ans %= M;
    }  
    cout << ans << endl;
    return 0;
}