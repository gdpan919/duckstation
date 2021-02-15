package com.github.stenzek.duckstation;

import android.app.Activity;
import android.content.ContentResolver;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;

import androidx.preference.PreferenceManager;

import java.util.Arrays;
import java.util.Comparator;
import java.util.Set;

public class GameList {
    private Activity mContext;
    private GameListEntry[] mEntries;
    private ListViewAdapter mAdapter;

    public GameList(Activity context) {
        mContext = context;
        mAdapter = new ListViewAdapter();
        mEntries = new GameListEntry[0];
    }

    private class GameListEntryComparator implements Comparator<GameListEntry> {
        @Override
        public int compare(GameListEntry left, GameListEntry right) {
            return left.getTitle().compareTo(right.getTitle());
        }
    }

    private static final String[] scanProjection = new String[]{
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
            DocumentsContract.Document.COLUMN_LAST_MODIFIED};

    private void scanDirectory(AndroidHostInterface hi, ContentResolver resolver, Uri treeUri, boolean recursive) {
        try {
            final String treeDocId = DocumentsContract.getTreeDocumentId(treeUri);
            final Uri queryUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, treeDocId);
            final Cursor cursor = resolver.query(queryUri, scanProjection, null, null, null);
            final int count = cursor.getCount();

            while (cursor.moveToNext()) {
                try {
                    final String mimeType = cursor.getString(2);
                    final String documentId = cursor.getString(0);
                    final Uri uri = DocumentsContract.buildDocumentUriUsingTree(treeUri, documentId);
                    if (DocumentsContract.Document.MIME_TYPE_DIR.equals(mimeType)) {
                        if (recursive)
                            scanDirectory(hi, resolver, Uri.parse(documentId), true);

                        continue;
                    }

                    final String uriString = uri.toString();
                    if (!hi.isScannableGameListFilename(uriString)) {
                        Log.d("GameList", "Skipping scanning " + uriString);
                        continue;
                    }

                    final long lastModified = cursor.getLong(3);
                    hi.scanGameListFile(uriString, lastModified);
                }
                catch (Exception e) {
                    e.printStackTrace();
                }
            }
            cursor.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void refresh(boolean invalidateCache, boolean invalidateDatabase) {
        final AndroidHostInterface hi = AndroidHostInterface.getInstance();
        final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(mContext);
        final ContentResolver resolver = mContext.getContentResolver();
        hi.beginGameListRefresh(invalidateCache, invalidateDatabase);

        final Set<String> recursiveDirs = PreferenceHelpers.getStringSet(prefs, "GameList/RecursivePaths");
        final Set<String> dirs = PreferenceHelpers.getStringSet(prefs, "GameList/Paths");
        if (recursiveDirs != null) {
            for (String path : recursiveDirs)
                scanDirectory(hi, resolver, Uri.parse(path), true);
        }
        if (dirs != null) {
            for (String path : dirs)
                scanDirectory(hi, resolver, Uri.parse(path), false);
        }

        hi.endGameListRefresh();
    }


    public void refresh(boolean invalidateCache, boolean invalidateDatabase, Activity parentActivity) {
        // Search and get entries from native code
        AndroidProgressCallback progressCallback = new AndroidProgressCallback(mContext);
        AsyncTask.execute(() -> {
            refresh(invalidateCache, invalidateDatabase);
            GameListEntry[] newEntries = AndroidHostInterface.getInstance().getGameListEntries();
            Arrays.sort(newEntries, new GameListEntryComparator());

            mContext.runOnUiThread(() -> {
                try {
                    progressCallback.dismiss();
                } catch (Exception e) {
                    Log.e("GameList", "Exception dismissing refresh progress");
                    e.printStackTrace();
                }
                mEntries = newEntries;
                mAdapter.notifyDataSetChanged();
            });
        });
    }

    public int getEntryCount() {
        return mEntries.length;
    }

    public GameListEntry getEntry(int index) {
        return mEntries[index];
    }

    private class ListViewAdapter extends BaseAdapter {
        @Override
        public int getCount() {
            return mEntries.length;
        }

        @Override
        public Object getItem(int position) {
            return mEntries[position];
        }

        @Override
        public long getItemId(int position) {
            return position;
        }

        @Override
        public int getViewTypeCount() {
            return 1;
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            if (convertView == null) {
                convertView = LayoutInflater.from(mContext)
                        .inflate(R.layout.game_list_view_entry, parent, false);
            }

            mEntries[position].fillView(convertView);
            return convertView;
        }
    }

    public BaseAdapter getListViewAdapter() {
        return mAdapter;
    }
}
