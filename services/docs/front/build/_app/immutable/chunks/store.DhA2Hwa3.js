import{ab as b,r as d,u as a,ac as l,ad as g,ae as c,af as o,C as p,Q as y,Y as S}from"./index-client.CkyIVMoC.js";function e(s,r){return s===r||(s==null?void 0:s[g])===r}function h(s={},r,u,i){return b(()=>{var f,n;return d(()=>{f=n,n=[],a(()=>{s!==u(...n)&&(r(s,...n),f&&e(u(...f),s)&&r(null,...f))})}),()=>{l(()=>{n&&e(u(...n),s)&&r(null,...n)})}}),s}function T(s,r,u){if(s==null)return r(void 0),c;const i=a(()=>s.subscribe(r,u));return i.unsubscribe?()=>i.unsubscribe():i}let t=!1;function k(s,r,u){const i=u[r]??(u[r]={store:null,source:p(void 0),unsubscribe:c});if(i.store!==s)if(i.unsubscribe(),i.store=s??null,s==null)i.source.v=void 0,i.unsubscribe=c;else{var f=!0;i.unsubscribe=T(s,n=>{f?i.source.v=n:S(i.source,n)}),f=!1}return y(i.source)}function q(){const s={};return o(()=>{for(var r in s)s[r].unsubscribe()}),s}function w(s){var r=t;try{return t=!1,[s(),t]}finally{t=r}}export{k as a,h as b,w as c,q as s};
