module.exports = {  
  apps: [  
    {  
      name: "Todo-401",  
      script: "index.js",  
      instances: "8",  
      exec_mode: "cluster",  
      watch: true,  
      max_memory_restart: "14",  
      log_date_format: "YYYY-MM-DD HH:mm Z",  
      env: {  
        NODE_ENV: "development",  
      },  
      env_production: {  
        NODE_ENV: "production",  
      },  
    },  
  ],  
};