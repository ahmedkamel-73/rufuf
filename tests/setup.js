
export const mockDB = {
  data: {books:[{id:1,title:'Test Book',cover_url:'/cdn/1.jpg'}], articles:[{id:1,title:'Test'}], push_subscriptions:[]},
  prepare(query){
    return {
      bind(...args){ this.args=args; return this; },
      async first(){ return {id:1,email:'test@test.com',role:'user'}; },
      async all(){ 
        if(query.includes('push_subscriptions')) return {results: mockDB.data.push_subscriptions};
        if(query.includes('books')) return {results: mockDB.data.books};
        return {results:[]};
      },
      async run(){ return {success:true}; }
    }
  }
};
export const mockEnv = {DB: mockDB, JWT_SECRET: 'a-very-long-secret-key-for-testing-32chars!', VAPID_PUBLIC_KEY:'test', ASSETS:{fetch:()=>new Response('asset')}};
