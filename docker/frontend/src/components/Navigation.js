import React from "react";
import { AppBar, Toolbar, Typography, Button, Box } from "@mui/material";
import { Link as RouterLink, useLocation } from "react-router-dom";

const Navigation = () => {
  const location = useLocation();

  return (
    <AppBar position="static">
      <Toolbar>
        <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
          BBHK Dashboard
        </Typography>
        <Box sx={{ display: "flex", gap: 2 }}>
          <Button 
            color="inherit" 
            component={RouterLink} 
            to="/"
            variant={location.pathname === "/" ? "outlined" : "text"}
          >
            Dashboard
          </Button>
          <Button 
            color="inherit" 
            component={RouterLink} 
            to="/programs"
            variant={location.pathname === "/programs" ? "outlined" : "text"}
          >
            Programs
          </Button>
          <Button 
            color="inherit" 
            component={RouterLink} 
            to="/targets"
            variant={location.pathname === "/targets" ? "outlined" : "text"}
          >
            Targets
          </Button>
        </Box>
      </Toolbar>
    </AppBar>
  );
};

export default Navigation;
