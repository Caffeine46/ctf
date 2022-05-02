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
vl a,x;

int main(){
    cin >>n>>k;
    a.resize(n);
    rep(i,n) cin >>a[i];
    x.resize(k);
    rep(i,k) cin >>x[i];
    reverse(x.begin(),x.end());
    vvi dp(k+1,vector<int> (n));
    rep(i,n) dp[0][i] = n-i;
    rep(i,k){
        rep(j,n){
            if(j == 0) dp[i+1][n-1-j] = 0;
            else{
                if(a[n-1-j] <= x[i]) dp[i+1][n-1-j] = dp[i+1][n-j];
                else dp[i+1][n-1-j] = min(dp[i][n-j],dp[i+1][n-j]+1);
            }
        }
    }
    print(dp[k][0]);
    newline;
    return 0;
}