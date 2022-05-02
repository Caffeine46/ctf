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

ll n;
vl a, b;


int main(){
    cin >>n;
    a.resize(n);
    b.resize(n);
    rep(i,n) cin >>a[i];
    rep(i,n) cin >> b[i];
    ll tmp = a[0];
    vl f(n);
    rep(i,n) f[i] = a[i] * (b[i] - 1);
    sort(f.begin(),f.end());
        
    rep(i,n){
        ll d = gcd(a[i],tmp);
        tmp /= d;
        if(tmp - f[0]%a[i] > f[0]/a[i]){
            cout << "No" << endl;
            return 0;
        }
        tmp *= a[i];
    }
    cout << "Yes" << endl;

    return 0;
}