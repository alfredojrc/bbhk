import React, { useState, useEffect } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Typography,
  Chip,
  Box,
  TextField,
  InputAdornment
} from "@mui/material";
import { Search } from "@mui/icons-material";
import api from "../services/api";

const Programs = () => {
  const [programs, setPrograms] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");

  useEffect(() => {
    const fetchPrograms = async () => {
      try {
        const response = await api.get("/api/programs", {
          params: { search: search || undefined }
        });
        setPrograms(response.data);
      } catch (error) {
        console.error("Error fetching programs:", error);
      } finally {
        setLoading(false);
      }
    };

    const timeoutId = setTimeout(fetchPrograms, 300);
    return () => clearTimeout(timeoutId);
  }, [search]);

  if (loading) return <div>Loading...</div>;

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Bug Bounty Programs
      </Typography>
      
      <TextField
        fullWidth
        variant="outlined"
        placeholder="Search programs..."
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        InputProps={{
          startAdornment: (
            <InputAdornment position="start">
              <Search />
            </InputAdornment>
          ),
        }}
        sx={{ mb: 3 }}
      />
      
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Program</TableCell>
              <TableCell>Platform</TableCell>
              <TableCell>Max Bounty</TableCell>
              <TableCell>Targets</TableCell>
              <TableCell>Status</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {programs.map((program) => (
              <TableRow key={program.id}>
                <TableCell>{program.name}</TableCell>
                <TableCell>
                  <Chip 
                    label={program.platform} 
                    size="small" 
                    color="primary"
                  />
                </TableCell>
                <TableCell>
                  {program.max_bounty ? `$${program.max_bounty}` : "N/A"}
                </TableCell>
                <TableCell>{program.target_count}</TableCell>
                <TableCell>
                  <Chip 
                    label={program.offers_bounties ? "Bounty" : "VDP"} 
                    size="small"
                    color={program.offers_bounties ? "success" : "default"}
                  />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
};

export default Programs;
