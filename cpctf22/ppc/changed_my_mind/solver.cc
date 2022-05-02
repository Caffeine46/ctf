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

ll n,m;
ll s,a,b;

// n: ノード数
// v: 重み付きグラフ
// s: 始点
vector<vector<pair<ll,int>>> v;
vl dist;
vi flag;
void dijk(int s){
    rep(i,n) dist[i]=(ll) 1 << 62;
    vector<bool> chk(n,false);
    priority_queue<pair<pair<ll,int>,int>> q;
    q.push({{0,s},0});
    dist[s]=0;
    
    while(!q.empty()){
        pair<pair<ll, int>,int> f = q.top(); q.pop();
        int ff = f.second;
        int u = f.first.second;
        if( dist[u] < f.first.first * (-1) ) continue;
        if(u != a) flag[u] = ff;
        rep(i,v[u].size()){
            int v2 = v[u][i].second;
            if(chk[v2]) continue;
            if(dist[v2] >= dist[u] + v[u][i].first){
                dist[v2] = dist[u] + v[u][i].first;
                //priority_queueはデフォルトでは大きい値を優先するため‐１をかける
                q.push({{dist[v2]*(-1), v2},flag[u]});
            }
        }
    }
}

int main(){
    cin >>n>>m;
    v.resize(n);
    dist.resize(n);
    flag.resize(n,0);
    rep(i,m){
        ll t1,t2,c;
        cin >>t1>>t2>>c;
        t1--;
        t2--;
        v[t1].push_back({c,t2});
        v[t2].push_back({c,t1});
    }
    cin >>s>>a>>b;
    s--;
    a--;
    b--;
    flag[a] = 1;
    dijk(s);
    ll cnt = 0;
    vl ans;
    rep(i,n){
        if(i == b) continue;
        if(i == s) continue;
        if(flag[i]){
            cnt++;
            ans.push_back(i+1);
        }
    }
    cout << cnt << endl;
    for(auto aa:ans) cout << aa << " ";
    newline;
    return 0;
}