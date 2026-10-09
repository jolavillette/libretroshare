/*
 * RetroShare
 * Copyright (C) 2021  Gioacchino Mazzurco <gio@retroshare.cc>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * SPDX-FileCopyrightText: Retroshare Team <contact@retroshare.cc>
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package org.retroshare.service;

import android.util.Log;
import android.content.Context;
import java.io.File;
import java.io.OutputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;


public class AssetHelper
{
    /**
     * Copy a whole asset directory, recursively, creating the destination as
     * needed. Used for the web interface, which is a tree of a few dozen files.
     *
     * AssetManager has no way to tell a directory from a file: list() returns
     * an empty array for both a file and an empty directory, so a leaf is
     * recognised by having no children and copied as a file. That is why a file
     * whose copy fails is reported, but an empty directory is not.
     *
     * @return false as soon as one file fails to copy, leaving the rest undone
     */
    public static boolean copyAssetDir(
        Context ctx, String assetPath, String destinationDirPath )
    {
        String[] children;
        try { children = ctx.getAssets().list(assetPath); }
        catch(IOException e)
        {
            Log.e(TAG, "Failure listing asset dir: " + assetPath + " " +
                       e.getMessage() );
            return false;
        }

        if(children == null || children.length == 0)
            return copyAsset(ctx, assetPath, destinationDirPath);

        File destinationDir = new File(destinationDirPath);
        if(!destinationDir.isDirectory() && !destinationDir.mkdirs())
        {
            Log.e(TAG, "Failure creating directory: " + destinationDirPath);
            return false;
        }

        for(String child : children)
            if(!copyAssetDir(
                   ctx, assetPath + "/" + child,
                   destinationDirPath + "/" + child ))
                return false;

        return true;
    }

    public static boolean copyAsset(
        Context ctx, String assetPath, String destinationFilePath )
    {
        Log.d(TAG, "copyAsset " + assetPath + " -> " + destinationFilePath);

        InputStream in;
        OutputStream out;

        try { in = ctx.getAssets().open(assetPath); }
        catch(Exception e)
        {
            Log.e(
                TAG,
                "Failure opening asset: " + assetPath + " " + e.getMessage() );
            return false;
        }

        try { out = new FileOutputStream(destinationFilePath); }
        catch(Exception e)
        {
            Log.e(
                TAG,
                "Failure opening destination: " + destinationFilePath + " " +
                e.getMessage() );
            return false;            
        }

        try
        {
            byte[] buf = new byte[1024];
            int len;
            while ((len = in.read(buf)) > 0) out.write(buf, 0, len);
        }
        catch(IOException e)
        {
            Log.e(
                TAG,
                "Failure coping: " + assetPath + " -> " + destinationFilePath +
                " " + e.getMessage() );
            return false;
        }

        try { in.close(); }
        catch(IOException e)
        {
            Log.e(TAG, "Failure closing: " + assetPath + " " + e.getMessage() );
            return false;
        }

        try { out.close(); }
        catch(IOException e)
        {
            Log.e(
                TAG,
                "Failure closing: " + destinationFilePath + " " +
                e.getMessage() );
            return false;
        }

        return true;
    }

    private static final String TAG = "RetroShare AssetHelper.java";
}
