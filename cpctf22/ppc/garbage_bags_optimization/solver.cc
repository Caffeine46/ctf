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

ll n,k;
vl a;

bool isOK(ll index) {
    ll tmp = 0;
    ll cnt = 0;
    rep(i,a.size()){
        if(a[i] + tmp > index){
            cnt++;
            if(cnt == k) return false;
            tmp = a[i];
        }
        else{
            tmp += a[i];
        }
    }
    return true;
}

ll binary_search() {
    ll ng = 0;
    ll ok =  1000000000000000001;
    while (abs(ok - ng) > 1) {
        ll mid = (ok + ng) / 2;
        if (isOK(mid)) ok = mid;
        else ng = mid;
    }
    return ok;
}

int main(){
    cin >>n >>k;
    a.resize(n);
    rep(i,n) cin >>a[i];
    ll ans = binary_search();
    cout << ans << endl;
    return 0;
}