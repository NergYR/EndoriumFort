#!/bin/bash

# Script to run both backend and frontend dev servers
# endoriumfort project

set -e

PROJECT_DIR="$(dirname "$(readlink -f "$0")")"
cd "$PROJECT_DIR"

echo "🚀 EndoriumFort Dev Environment"
echo "================================"

# Kill any existing processes
echo "🛑 Cleaning up existing processes..."
pkill -9 -f endoriumfort_backend 2>/dev/null || true
pkill -9 -f "vite" 2>/dev/null || true
sleep 1

# Backend compilation and startup
echo ""
echo "📦 Building backend..."
cd "$PROJECT_DIR/backend/build"
make -j$(nproc) 2>&1 | tail -5

echo "▶️  Starting backend (port 8080)..."
./endoriumfort_backend > /tmp/backend.log 2>&1 &
BACKEND_PID=$!
echo "   PID: $BACKEND_PID"

# Wait for backend to be ready
sleep 2
if ! kill -0 $BACKEND_PID 2>/dev/null; then
  echo "❌ Backend failed to start!"
  cat /tmp/backend.log
  exit 1
fi

# Frontend
echo ""
echo "📱 Starting frontend dev server (port 5173)..."
cd "$PROJECT_DIR/frontend"
npm run dev > /tmp/frontend.log 2>&1 &
FRONTEND_PID=$!
echo "   PID: $FRONTEND_PID"

sleep 3

# Check both are running
if kill -0 $BACKEND_PID 2>/dev/null && kill -0 $FRONTEND_PID 2>/dev/null; then
  echo ""
  echo "✅ All services running!"
  echo ""
  echo "📝 Access points:"
  echo "   Frontend: http://localhost:5173"
  echo "   Backend:  http://localhost:8080"
  echo ""
  echo "🎨 Default credentials: admin/admin"
  echo ""
  echo "📊 Logs:"
  echo "   Backend:  tail -f /tmp/backend.log"
  echo "   Frontend: tail -f /tmp/frontend.log"
  echo ""
  echo "💡 Press Ctrl+C to stop all services"
  
  # Wait for interrupt
  trap "echo; echo 'Stopping services...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true; echo 'Done.'; exit 0" SIGINT
  
  wait
else
  echo "❌ One or more services failed to start"
  [ -f /tmp/backend.log ] && echo "Backend log:" && cat /tmp/backend.log
  [ -f /tmp/frontend.log ] && echo "Frontend log:" && cat /tmp/frontend.log
  exit 1
fi
