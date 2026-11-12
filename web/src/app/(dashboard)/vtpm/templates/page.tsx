"use client";

import * as React from "react";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useApi, useVTPM } from "@/hooks";

export default function VTPMTemplatesPage() {
  const vtpm = useVTPM();
  const { data, loading, error } = useApi(() => vtpm.listTemplates(), []);
  const templates = data?.templates ?? [];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">vTPM Templates</h1>
      <Card>
        <CardHeader>
          <CardTitle>Templates</CardTitle>
        </CardHeader>
        <CardContent>
          {loading && <p>Loading…</p>}
          {error && <p role="alert">{String(error)}</p>}
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>Name</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {templates.map((t) => (
                <TableRow key={t.id}>
                  <TableCell>{t.id}</TableCell>
                  <TableCell>{t.name}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
