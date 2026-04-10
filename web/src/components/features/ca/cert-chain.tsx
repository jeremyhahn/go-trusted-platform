"use client";

import * as React from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { Certificate } from "@/types/security";
import { ChevronDown } from "lucide-react";

interface CertChainProps {
  chain: Certificate[];
  currentCertId?: string;
}

/**
 * Certificate chain visualization component
 *
 * Displays the certificate trust chain from root to leaf:
 * Root CA -> Intermediate CA(s) -> Leaf Certificate
 *
 * Features:
 * - Visual hierarchy with connecting lines
 * - Highlight current certificate
 * - Status indicators
 * - Expiration warnings
 */
export function CertChain({ chain, currentCertId }: CertChainProps) {
  if (chain.length === 0) {
    return (
      <Card>
        <CardContent className="py-8 text-center text-muted-foreground">
          No certificate chain available
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Certificate Chain</CardTitle>
        <CardDescription>
          Trust chain from root certificate to leaf certificate
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-0">
          {chain.map((cert, index) => {
            const isCurrent = cert.id === currentCertId;
            const isExpired = new Date(cert.notAfter) < new Date();
            const isExpiringSoon =
              new Date(cert.notAfter).getTime() - new Date().getTime() <
              30 * 24 * 60 * 60 * 1000;

            return (
              <div key={cert.id}>
                <div
                  className={`
                    relative p-4 rounded-lg border
                    ${isCurrent
                      ? "bg-accent border-primary"
                      : "bg-card border-border"
                    }
                  `}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-2">
                        <Badge variant="outline" className="capitalize text-xs">
                          {cert.type}
                        </Badge>
                        <Badge
                          variant={
                            cert.status === "active"
                              ? "default"
                              : cert.status === "revoked"
                              ? "destructive"
                              : "secondary"
                          }
                          className="text-xs"
                        >
                          {cert.status}
                        </Badge>
                        {isCurrent && (
                          <Badge variant="default" className="text-xs">
                            Current
                          </Badge>
                        )}
                      </div>
                      <div className="font-medium text-sm mb-1 truncate">
                        {cert.subject}
                      </div>
                      <div className="text-xs text-muted-foreground truncate">
                        Issuer: {cert.issuer}
                      </div>
                      <div className="text-xs text-muted-foreground mt-1">
                        Serial: <code>{cert.serialNumber}</code>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-xs text-muted-foreground">Expires</div>
                      <div
                        className={`text-sm font-medium ${
                          isExpired
                            ? "text-destructive"
                            : isExpiringSoon
                            ? "text-orange-500"
                            : ""
                        }`}
                      >
                        {new Date(cert.notAfter).toLocaleDateString()}
                      </div>
                      {isExpiringSoon && !isExpired && (
                        <div className="text-xs text-orange-500 mt-1">
                          Expiring soon
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Connector between certificates */}
                {index < chain.length - 1 && (
                  <div className="flex justify-center py-2">
                    <ChevronDown className="h-5 w-5 text-muted-foreground" />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
