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
  Box
} from "@mui/material";
import api from "../services/api";

const Targets = () => {
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchTargets = async () => {
      try {
        const response = await api.get("/api/targets");
        setTargets(response.data);
      } catch (error) {
        console.error("Error fetching targets:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchTargets();
  }, []);

  if (loading) return <div>Loading...</div>;

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Attack Targets
      </Typography>
      
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Target</TableCell>
              <TableCell>Type</TableCell>
              <TableCell>Program</TableCell>
              <TableCell>Severity</TableCell>
              <TableCell>Last Scanned</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {targets.map((target) => (
              <TableRow key={target.id}>
                <TableCell>{target.asset_identifier}</TableCell>
                <TableCell>
                  <Chip 
                    label={target.asset_type || "unknown"} 
                    size="small"
                  />
                </TableCell>
                <TableCell>{target.program_name}</TableCell>
                <TableCell>
                  {target.severity_rating && (
                    <Chip 
                      label={target.severity_rating}
                      size="small"
                      color={
                        target.severity_rating === "critical" ? "error" :
                        target.severity_rating === "high" ? "warning" :
                        target.severity_rating === "medium" ? "info" : "default"
                      }
                    />
                  )}
                </TableCell>
                <TableCell>
                  {target.last_scanned ? 
                    new Date(target.last_scanned).toLocaleDateString() : 
                    "Never"
                  }
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
};

export default Targets;
